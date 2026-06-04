/**
 * LLM-Chat-Frontend — SSE-Streaming, Follow-Up-Submit, Auto-Scroll.
 *
 * Wird von `chat/conversation.html` als Alpine-`x-data="llmChat(...)"`
 * konsumiert. Reine UX-Logik. Sicherheits-Regeln:
 *   - SSE-Token-Deltas sind Text — wir setzen `textContent`, niemals
 *     `innerHTML`. Die finale, persistierte Assistant-Message wird vom
 *     Server beim naechsten Page-Load durch den `llm_safe`-Filter
 *     gejagt; waehrend des Streamings reicht reiner Plain-Text.
 *   - CSRF-Token kommt aus `<meta name="csrf-token">` (analog
 *     `bulk_ack.js`).
 *   - Folge-Message wird per `fetch(..., {credentials: 'same-origin'})`
 *     an die JSON-API geschickt — das passende Backend (`POST
 *     /chat/<id>/messages`) erwartet `application/json`-Body.
 */

(function () {
  "use strict";

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function llmChat({ streamUrl, postMessageUrl, autoStart }) {
    return {
      streaming: false,
      draft: "",
      eventSource: null,
      streamBuffer: "",
      error: null,

      init() {
        if (autoStart) {
          // Letzte Message ist vom User -> Antwort steht aus.
          this.$nextTick(() => this.connect(streamUrl));
        }
      },

      connect(url) {
        if (this.eventSource) {
          this.eventSource.close();
          this.eventSource = null;
        }
        const target = document.getElementById("stream-target");
        if (!target) return;
        const bubble = target.querySelector("[data-stream-bubble]");
        if (bubble) bubble.textContent = "";
        this.streamBuffer = "";
        target.classList.remove("hidden");
        this.streaming = true;
        this.error = null;

        const es = new EventSource(url, { withCredentials: true });
        this.eventSource = es;

        es.onmessage = (ev) => {
          // Default-Event = Token-Delta (siehe `_sse_payload("message",
          // delta)` im Backend). `ev.data` kann mehrere Zeilen enthalten,
          // die wir mit `\n` wieder zusammenfuegen.
          this.streamBuffer += ev.data;
          if (bubble) {
            bubble.textContent = this.streamBuffer;
          }
          this.scrollToBottom();
        };

        es.addEventListener("done", (ev) => {
          this.closeStream();
          // Page-Refresh: die endgueltige Message wird vom Backend
          // persistiert; ein Reload rendert sie korrekt durch
          // `llm_safe` und aktualisiert die Token-Counts.
          setTimeout(() => window.location.reload(), 200);
          void ev;
        });

        es.addEventListener("error", (ev) => {
          // Naked EventSource.onerror trifft auch bei Verbindungsende —
          // wir unterscheiden via readyState. CLOSED = sauber zu Ende.
          if (es.readyState === EventSource.CLOSED) {
            this.closeStream();
            return;
          }
          this.error = "Stream error";
          this.$dispatch("toast", { msg: "Stream error", kind: "error" });
          this.closeStream();
          void ev;
        });
      },

      closeStream() {
        if (this.eventSource) {
          this.eventSource.close();
          this.eventSource = null;
        }
        this.streaming = false;
      },

      async submitFollowup() {
        const content = (this.draft || "").trim();
        if (!content || this.streaming) return;
        this.streaming = true;
        this.error = null;
        try {
          const res = await fetch(postMessageUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/json",
              "X-CSRFToken": csrfToken(),
              Accept: "application/json",
            },
            body: JSON.stringify({ content }),
          });
          let payload = null;
          try {
            payload = await res.json();
          } catch (e) {
            payload = null;
          }
          if (!res.ok) {
            const msg =
              (payload && (payload.message || payload.error)) ||
              `Error ${res.status}`;
            throw new Error(msg);
          }
          this.draft = "";
          const nextStreamUrl =
            (payload && payload.stream_url) || streamUrl;
          this.connect(nextStreamUrl);
        } catch (e) {
          this.streaming = false;
          this.error = e.message || "Unknown error";
          this.$dispatch("toast", { msg: this.error, kind: "error" });
        }
      },

      scrollToBottom() {
        const list = document.getElementById("message-list");
        if (!list) return;
        // Sanftes Scrollen, aber nur wenn der User nahe am Ende ist —
        // sonst stoeren wir ihn beim Hochscrollen waehrend des Streams.
        const nearBottom =
          window.innerHeight + window.scrollY >=
          document.body.offsetHeight - 200;
        if (nearBottom) {
          window.scrollTo({
            top: document.body.scrollHeight,
            behavior: "smooth",
          });
        }
      },
    };
  }

  document.addEventListener("alpine:init", () => {
    window.Alpine.data("llmChat", llmChat);
  });
  // Fallback bei spaeter Initialisierung.
  window.llmChat = llmChat;
})();
