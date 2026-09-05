"""Чаты с нейронкой — на фейковом OpenRouter.

Проверяется весь путь целиком: создание чата, отправка реплики, разбор
потока SSE и сохранение ответа в историю. Настоящий OpenRouter не
дёргается — адрес подменён в conftest ещё до импорта приложения.
"""

from conftest import FAKE_AI_REPLY


def _sse_payloads(raw):
    """Разбирает поток `data: {...}` в список объектов."""
    import json

    out = []
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("data:"):
            chunk = line[5:].strip()
            if chunk and chunk != "[DONE]":
                out.append(json.loads(chunk))
    return out


def test_ai_requires_login(client):
    assert client.post("/api/ai/chat").status_code == 302
    assert client.post("/api/ai/chat/чужой/send", json={"text": "привет"}).status_code == 302


def test_ai_chat_create(auth_client):
    resp = auth_client.post("/api/ai/chat")
    assert resp.status_code == 200
    assert resp.get_json()["id"]


def test_ai_send_streams_and_saves(auth_client, fake_openrouter):
    chat_id = auth_client.post("/api/ai/chat").get_json()["id"]

    resp = auth_client.post(f"/api/ai/chat/{chat_id}/send", json={"text": "Как дела?"})
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"

    frames = _sse_payloads(resp.data)
    assert not any("error" in f for f in frames), frames

    # Заголовок долетает первым кадром — страница показывает его сразу,
    # не дожидаясь конца ответа.
    assert frames[0].get("title") == "Как дела?"

    # Куски пришли по одному и склеились в целый ответ.
    assert "".join(f["delta"] for f in frames if "delta" in f) == FAKE_AI_REPLY
    assert frames[-1].get("done") is True
    assert frames[-1].get("text") == FAKE_AI_REPLY

    # Модели ушла и системная подсказка, и реплика человека.
    sent = fake_openrouter.last_request
    assert sent["stream"] is True
    assert sent["messages"][0]["role"] == "system"
    assert sent["messages"][-1]["content"] == "Как дела?"

    # И то же самое лежит в истории чата: после перезагрузки страницы
    # разговор должен выглядеть ровно так, как его видели на экране.
    saved = auth_client.get(f"/api/ai/chat/{chat_id}").get_json()
    msgs = saved["messages"]
    assert msgs[-2]["role"] == "user" and msgs[-2]["text"] == "Как дела?"
    assert msgs[-1]["role"] == "assistant" and msgs[-1]["text"] == FAKE_AI_REPLY


def test_ai_send_rejects_empty(auth_client):
    chat_id = auth_client.post("/api/ai/chat").get_json()["id"]
    resp = auth_client.post(f"/api/ai/chat/{chat_id}/send", json={"text": "   "})
    assert resp.status_code == 400
    assert resp.get_json().get("error")


def test_ai_send_unknown_chat(auth_client):
    resp = auth_client.post("/api/ai/chat/нет-такого/send", json={"text": "привет"})
    assert resp.status_code == 404
