#!/usr/bin/env python3
"""
MCP Server for OCR Image Recognition
Provides tools for performing OCR on single images via remote API
"""

import argparse
import base64
import hashlib
import logging
import os
import sys
from time import sleep
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Fallback for Python < 3.11

import mcp.server.stdio
import requests
from mcp.server import Server
from mcp.types import TextContent, Tool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ocr-mcp-server")

# Initialize MCP server
app = Server("ocr-server")

# Global configuration
config = {}


def load_config(config_path: str) -> dict[str, Any]:
    """
    Load configuration from TOML file.

    Args:
        config_path: Path to the TOML configuration file

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, "rb") as f:
            conf = tomllib.load(f)
        logger.info(f"Configuration loaded from {config_path}")

        # Validate required configuration fields
        required_fields = [
            "perm_url",
            "start_url",
            "status_url",
            "auth_token",
            "auth_uuid",
            "origin",
        ]
        missing_fields = [field for field in required_fields if not conf.get(field)]
        if missing_fields:
            logger.error(f"Missing required configuration fields: {missing_fields}")
            sys.exit(1)

        return conf
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)


def calculate_sha1_hash(input_data: str) -> str:
    """
    Calculate SHA-1 hash for base64 image data.

    Args:
        input_data: Base64 encoded image string

    Returns:
        SHA-1 hash in hexadecimal format
    """
    if isinstance(input_data, str):
        input_data = input_data.encode("utf-8")

    sha1_hash = hashlib.sha1(input_data).hexdigest()
    return sha1_hash


def auth() -> dict[str, str]:
    """
    Get authentication credentials from configuration.

    Returns:
        Dictionary containing token, uuid, and cookie
    """
    return {
        "token": config.get("auth_token", ""),
        "uuid": config.get("auth_uuid", ""),
        "cookie": config.get("auth_cookie", ""),
    }


def get_single_api_perm_token() -> dict[str, Any]:
    """
    Get permission token for single OCR operation.

    Returns:
        Response JSON containing token

    Raises:
        Exception: If API request fails or returns invalid response
    """
    url = config.get("perm_url", "")
    mode = config.get("mode", "single")
    auth_json = auth()
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json;charset=UTF-8",
        "origin": config.get("origin", ""),
        "referer": config.get("origin", "") + "/",
        "x-auth-token": auth_json["token"],
        "x-auth-uuid": auth_json["uuid"],
    }

    timeout = config.get("timeout_secs", 30)
    verify_certs = not config.get("accept_invalid_certs", False)

    try:
        response = requests.post(
            url,
            headers=headers,
            json={"mode": mode},
            timeout=timeout,
            verify=verify_certs,
        )
        response.raise_for_status()
        result = response.json()

        # Validate response structure
        if not result.get("data") or not result["data"].get("token"):
            raise ValueError(f"Invalid API response: missing token. Response: {result}")

        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get permission token: {e}")
        raise


def to_image_data(image_path: str) -> tuple[str, int, str]:
    """
    Convert image file to base64 data URL.

    Args:
        image_path: Path to the image file

    Returns:
        Tuple of (data_url, image_size, image_name)
    """
    with open(image_path, "rb") as f:
        image_bytes = f.read()

    image_size = len(image_bytes)
    image_name = os.path.basename(image_path)
    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    image_data = "data:image/png;base64," + image_b64
    return image_data, image_size, image_name


def start_ocr(token: str, image_data: str, image_size: int, image_name: str) -> str:
    """
    Start OCR processing job.

    Args:
        token: Permission token
        image_data: Base64 encoded image data
        image_size: Size of image in bytes
        image_name: Name of the image file

    Returns:
        Job status ID
    """
    url = config.get("start_url", "")
    auth_json = auth()
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json;charset=UTF-8",
        "cookie": auth_json["cookie"],
        "origin": config.get("origin", ""),
        "priority": "u=1, i",
        "referer": config.get("origin", "") + "/",
        "x-auth-token": auth_json["token"],
        "x-auth-uuid": auth_json["uuid"],
    }

    hash_value = calculate_sha1_hash(image_data)
    payload = {
        "token": token,
        "hash": hash_value,
        "name": image_name,
        "size": image_size,
        "dataUrl": image_data,
        "result": {},
        "status": "processing",
        "isSuccess": False,
    }

    try:
        timeout = config.get("timeout_secs", 30)
        verify_certs = not config.get("accept_invalid_certs", False)
        response = requests.post(
            url, headers=headers, json=payload, verify=verify_certs, timeout=timeout
        )
        response.raise_for_status()
        res = response.json()

        logger.info(f"OCR started: {res}")

        # Validate response structure
        if not res.get("data") or not res["data"].get("jobStatusId"):
            raise ValueError(
                f"Invalid API response: missing jobStatusId. Response: {res}"
            )

        return res["data"]["jobStatusId"]
    except requests.exceptions.RequestException as e:
        logger.error(f"OCR request failed: {e}")
        raise
    except (KeyError, ValueError) as e:
        logger.error(f"OCR response validation failed: {e}")
        raise


def get_ocr_result(job_status_id: str) -> dict[str, Any]:
    """
    Get OCR processing result.

    Args:
        job_status_id: Job status ID

    Returns:
        Response JSON containing OCR result

    Raises:
        Exception: If API request fails
    """
    url = config.get("status_url", "")
    auth_json = auth()

    headers = {
        "accept": "application/json, text/plain, */*",
        "cookie": auth_json["cookie"],
        "origin": config.get("origin", ""),
        "referer": config.get("origin", "") + "/",
        "X-AUTH-TOKEN": auth_json["token"],
        "X-AUTH-UUID": auth_json["uuid"],
    }
    params = {"jobStatusId": job_status_id}
    timeout = config.get("timeout_secs", 30)
    verify_certs = not config.get("accept_invalid_certs", False)

    try:
        response = requests.get(
            url, headers=headers, params=params, verify=verify_certs, timeout=timeout
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get OCR result: {e}")
        raise


def wait_for_ocr_result(
    job_status_id: str, interval: float = None, max_attempts: int = None
) -> dict[str, Any]:
    """
    Poll OCR status until job finishes or attempts run out.

    Args:
        job_status_id: Job status ID
        interval: Polling interval in seconds (from config if None)
        max_attempts: Maximum number of polling attempts (from config if None)

    Returns:
        Final OCR result

    Raises:
        TimeoutError: If max polling attempts reached without completion
    """
    if interval is None:
        interval = config.get("poll_interval_ms", 3000) / 1000.0
    if max_attempts is None:
        max_attempts = config.get("poll_max_attempts", 10)

    # Initial delay before first poll
    initial_delay = config.get("poll_initial_delay_ms", 500) / 1000.0
    if initial_delay > 0:
        sleep(initial_delay)

    last_result = None

    for attempt in range(1, max_attempts + 1):
        last_result = get_ocr_result(job_status_id)
        data = last_result.get("data", {})
        is_ended = data.get("isEnded")
        percent = data.get("perc")

        if is_ended or last_result.get("code") != 1:
            return last_result

        logger.info(
            f"OCR still processing (attempt {attempt}/{max_attempts}, perc={percent})"
        )

        if attempt < max_attempts:
            sleep(interval)

    # If we get here, we've exhausted all attempts
    logger.warning(f"OCR polling timeout after {max_attempts} attempts")
    if last_result:
        return last_result
    else:
        raise TimeoutError(
            f"OCR processing timeout after {max_attempts} polling attempts"
        )


def perform_ocr(image_path: str) -> dict[str, Any]:
    """
    Perform OCR on a single image and return the result.

    Args:
        image_path: Path to the image file

    Returns:
        OCR result dictionary
    """
    # Validate image path
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image file not found: {image_path}")

    # Convert image to data URL
    image_data, image_size, image_name = to_image_data(image_path)
    logger.info(f"Processing image: {image_name} ({image_size} bytes)")

    # Get token and start OCR
    token = get_single_api_perm_token()["data"]["token"]
    logger.info(f"Got token: {token}")

    job_status_id = start_ocr(token, image_data, image_size, image_name)
    logger.info(f"OCR Job Status ID: {job_status_id}")

    # Wait for result
    ocr_result = wait_for_ocr_result(str(job_status_id))

    return ocr_result


@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    List available tools.
    """
    return [
        Tool(
            name="ocr_image",
            description=(
                "Perform OCR (Optical Character Recognition) on a single image file. "
                "This tool analyzes the image and extracts text content from it. "
                "Supports common image formats like PNG, JPG, JPEG, etc. "
                "Returns the recognized text and related information."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Absolute path to the image file for OCR processing",
                    },
                },
                "required": ["image_path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """
    Handle tool calls.
    """
    if name != "ocr_image":
        raise ValueError(f"Unknown tool: {name}")

    if not isinstance(arguments, dict) or "image_path" not in arguments:
        raise ValueError("Invalid arguments: 'image_path' is required")

    image_path = arguments["image_path"]

    try:
        # Perform OCR
        result = perform_ocr(image_path)

        # Extract text from result
        if result and result.get("data") and result["data"].get("isEnded"):
            data = result["data"]

            # Extract text from ydResp (Youdao response)
            text_lines = []
            if "ydResp" in data and "words_result" in data["ydResp"]:
                for word_result in data["ydResp"]["words_result"]:
                    text_lines.append(word_result.get("words", ""))

            text_content = "\n".join(text_lines) if text_lines else data.get("text", "")
            confidence = data.get("perc", 0)
            word_count = data.get("ydResp", {}).get("words_result_num", 0)

            response = {
                "success": True,
                "text": text_content,
                "word_count": word_count,
                "confidence": confidence,
                "image_name": os.path.basename(image_path),
            }

            result_text = f"OCR Result:\n\n{text_content}\n\n"
            result_text += f"Word Count: {word_count}\n"
            if confidence:
                result_text += f"Confidence: {confidence}%\n"

            return [
                TextContent(
                    type="text",
                    text=result_text,
                )
            ]
        else:
            return [
                TextContent(
                    type="text",
                    text=f"OCR processing did not complete successfully. Result: {result}",
                )
            ]

    except FileNotFoundError as e:
        return [
            TextContent(
                type="text",
                text=f"Error: {str(e)}",
            )
        ]
    except Exception as e:
        logger.error(f"Error performing OCR: {e}", exc_info=True)
        return [
            TextContent(
                type="text",
                text=f"Error performing OCR: {str(e)}",
            )
        ]


async def main():
    """
    Main entry point for the MCP server.
    """
    global config

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="MCP Server for OCR Image Recognition")
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=True,
        help="Path to the TOML configuration file",
    )
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
