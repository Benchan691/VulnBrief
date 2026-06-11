import argparse
import json
import os
import requests
import threading
import time
import sys

CONFIG_FILE = "config.json"


def load_config(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

    required = [
        "BASE",
        "AUTH_TOKEN",
        "X_AUTH_TOKEN",
        "conversation_id",
        "modelName",
        "ownerAccount",
        "platformId",
        "qaType",
        "fromSource",
        "isUseThink",
        "userPrompt",
    ]

    missing = [key for key in required if key not in config]
    if missing:
        raise KeyError(f"Missing required config keys: {', '.join(missing)}")

    return config


def build_headers(config: dict):
    return {
        "Authorization": f"Bearer {config['AUTH_TOKEN']}",
        "x-authorization": f"Bearer {config['X_AUTH_TOKEN']}",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": config["BASE"],
        "Origin": config["BASE"],
        "User-Agent": "Mozilla/5.0",
    }


def listen_sse(config: dict):
    final_answer = []
    url = f"{config['BASE']}/smartbot/openapi/im/sse/createSse"

    params = {
        "uid": config["conversation_id"],
        "platformId": config["platformId"],
        "type": "normal_chat",
    }

    headers = build_headers(config)
    headers["Accept"] = "text/event-stream"

    with requests.get(
        url,
        headers=headers,
        params=params,
        stream=True,
        timeout=(10, None),
    ) as r:
        print("SSE status:", r.status_code)

        for raw_line in r.iter_lines(chunk_size=1):
            if not raw_line:
                continue
            line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
            if not line.startswith("data:"):
                continue

            raw = line[5:].strip()
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if obj.get("type") == "heartbeat":
                continue

            event = obj.get("event")
            if event == "message":
                chunk = obj.get("answer_content", "")
                final_answer.append(chunk)
                print(chunk, end="", flush=True)
            elif event == "message_end":
                print("\n\n--- FINAL ANSWER ---")
                print("".join(final_answer))
                break


def send_message(config: dict, text: str):
    url = f"{config['BASE']}/smartbot/openapi/im/biz/createChat"

    headers = build_headers(config)
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json, text/plain, */*"

    payload = {
        "content": text,
        "conversationId": config["conversation_id"],
        "datasets": {"datasetIds": [], "fileIds": []},
        "fromSource": config["fromSource"],
        "isUseThink": config["isUseThink"],
        "modelName": config["modelName"],
        "ownerAccount": config["ownerAccount"],
        "platformId": config["platformId"],
        "qaType": config["qaType"],
        "userPrompt": config["userPrompt"],
    }

    r = requests.post(url, headers=headers, json=payload, timeout=30)
    print("POST status:", r.status_code)
    print("POST response:", r.text)


def main():
    parser = argparse.ArgumentParser(description="Send a message to SmartBot using JSON config.")
    parser.add_argument("message", nargs="?", help="Message text to send")
    parser.add_argument("--config", default=CONFIG_FILE, help="JSON config file path")
    args = parser.parse_args()

    if not args.message:
        print("Usage: python main.py \"your message here\"")
        sys.exit(1)

    config = load_config(args.config)

    thread = threading.Thread(target=listen_sse, args=(config,))
    thread.start()

    time.sleep(2)
    send_message(config, args.message)
    thread.join()


if __name__ == "__main__":
    main()
