import json
from collections.abc import Mapping

import pytest

from labcourt.adapters.m8_qwen_agent import StdlibM8QwenAgentClient
from labcourt.contracts.m8_agent_chat import M8AgentFailureCode
from labcourt.ports.m8_agent_chat import (
    M8AgentProviderDeltaKind,
    M8AgentProviderError,
    M8AgentProviderRequest,
)


class _Response:
    status = 200

    def __init__(self, lines: list[bytes]) -> None:
        self._lines = iter(lines)

    def readline(self, limit: int = -1) -> bytes:
        line = next(self._lines, b"")
        return line[:limit] if limit >= 0 else line


class _Connection:
    def __init__(self, lines: list[bytes]) -> None:
        self.response = _Response(lines)
        self.closed = False
        self.request_headers: Mapping[str, str] = {}

    def request(self, method: str, target: str, body: bytes, headers: Mapping[str, str]) -> None:
        assert method == "POST"
        assert target.endswith("/compatible-mode/v1/chat/completions")
        assert json.loads(body)["stream"] is True
        self.request_headers = headers

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> "_Connection":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _line(value: object) -> bytes:
    return b"data: " + json.dumps(value, ensure_ascii=False).encode() + b"\n"


def test_qwen_sse_transport_preserves_utf8_and_fragmented_tool_arguments() -> None:
    connection = _Connection(
        [
            _line(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call-1",
                                        "function": {
                                            "name": "query_knowledge",
                                            "arguments": '{"query":"护',
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            ),
            _line(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {"arguments": '目镜"}'},
                                    }
                                ]
                            },
                        }
                    ]
                }
            ),
            _line(
                {
                    "choices": [],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 3},
                }
            ),
            b"data: [DONE]\n",
        ]
    )
    client = StdlibM8QwenAgentClient(
        endpoint=(
            "https://dashscope.aliyuncs.com/api/v1/services/aigc/"
            "text-generation/generation/compatible-mode/v1/chat/completions"
        ),
        api_key="demo-key",
        connection_factory=lambda *_args, **_kwargs: connection,
    )
    deltas = tuple(
        client.stream(
            M8AgentProviderRequest(
                body=b'{"stream":true}', timeout_seconds=1, max_response_bytes=16_384
            )
        )
    )
    assert [item.kind for item in deltas] == [
        M8AgentProviderDeltaKind.TOOL,
        M8AgentProviderDeltaKind.TOOL,
        M8AgentProviderDeltaKind.USAGE,
        M8AgentProviderDeltaKind.DONE,
    ]
    assert "".join(item.tool_arguments_delta for item in deltas) == '{"query":"护目镜"}'
    assert connection.closed
    assert connection.request_headers["Authorization"] == "Bearer demo-key"


def test_qwen_sse_transport_rejects_interrupted_and_oversized_streams() -> None:
    for lines, expected, limit in (
        (
            [_line({"choices": [{"index": 0, "delta": {"content": "partial"}}]})],
            M8AgentFailureCode.STREAM_INTERRUPTED,
            256,
        ),
        (
            [b"data: " + b"x" * 100 + b"\n"],
            M8AgentFailureCode.RESPONSE_TOO_LARGE,
            64,
        ),
    ):
        connection = _Connection(lines)
        client = StdlibM8QwenAgentClient(
            endpoint="https://example.com/compatible-mode/v1/chat/completions",
            api_key="demo-key",
            connection_factory=lambda *_args, _connection=connection, **_kwargs: _connection,
        )
        with pytest.raises(M8AgentProviderError) as captured:
            tuple(
                client.stream(
                    M8AgentProviderRequest(
                        body=b'{"stream":true}',
                        timeout_seconds=1,
                        max_response_bytes=limit,
                    )
                )
            )
        assert captured.value.failure_code == expected
