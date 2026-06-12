// Per-Group-AI-Chat — Alpine-Component (ADR-0055, Block AE).
//
// Wird von `servers/group_chat.html` als `x-data="groupChat(...)"` konsumiert.
// UX-Logik: User-Message posten -> SSE-Stream der Assistant-Antwort.
//
// Sicherheits-Regeln (CLAUDE.md / ADR-0055):
//   - SSE-Token-Deltas sind PLAIN TEXT. Wir setzen ausschliesslich
//     `textContent` (`+=`), niemals `innerHTML` — kein XSS-Sink auf dem
//     Stream-Pfad. Die persistierte Assistant-Message wird beim naechsten
//     Page-Load von Jinja autoescaped gerendert.
//   - Die User-Bubble kommt als server-gerendertes (autoescaped) Fragment
//     `bubble_html` aus der JSON-Response. Es stammt vom Single-Source-Partial
//     `_partials/group_chat_message.html`, also vertrauenswuerdig — wir
//     fuegen es via `insertAdjacentHTML` ein.
//   - CSRF-Token aus `<meta name="csrf-token">` als `X-CSRFToken`-Header
//     (analog dem entfernten llm_chat.js).
//
// Die STREAMING-Assistant-Bubble bauen wir client-seitig mit demselben
// Klassen-/ID-Schema wie das Partial (`sd-msg sd-msg--assistant`,
// `id="chat-msg-stream"`, `data-msg-role="assistant"`, `data-test="chat-msg"`,
// `.sd-msg__bubble[data-msg-bubble]`) — Single-Source-Doktrin im Geist: der
// Drift-Test deckt das Partial ab, das JS spiegelt dieselbe Struktur.

'use strict';

function csrfToken() {
  var meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? (meta.getAttribute('content') || '') : '';
}

function groupChat(opts) {
  var cfg = opts || {};
  return {
    draft: '',
    busy: false,
    empty: true,
    eventSource: null,

    init: function () {
      // Empty-State sichtbar gdw. der Thread keine persistierten Messages traegt.
      var msgs = this.$refs.messages;
      this.empty = !(msgs && msgs.querySelector('[data-test="chat-msg"]'));
      // Esc -> zurueck zur Detail-View. Listener am Component-Root, damit er
      // mit dem Sub-View-Swap (HTMX) wieder verschwindet.
      var self = this;
      this._onKey = function (e) {
        if (e.key === 'Escape') {
          e.preventDefault();
          self.back();
        }
      };
      this.$root.addEventListener('keydown', this._onKey);
      this.$nextTick(function () {
        if (self.$refs.input) self.$refs.input.focus();
        self.scrollToBottom();
      });
    },

    destroy: function () {
      this.closeStream();
      if (this._onKey) this.$root.removeEventListener('keydown', this._onKey);
    },

    onKeyDown: function (e) {
      // Enter sendet, Shift+Enter = Zeilenumbruch.
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.send();
      }
    },

    sendSuggestion: function (text) {
      this.draft = text;
      this.send();
    },

    send: function () {
      var content = (this.draft || '').trim();
      if (!content || this.busy) return;
      var self = this;
      this.busy = true;
      this.empty = false;
      this.draft = '';

      fetch(cfg.postMessageUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken(),
          Accept: 'application/json',
        },
        body: JSON.stringify({ content: content }),
      })
        .then(function (res) {
          return res.json().catch(function () { return null; }).then(function (payload) {
            return { ok: res.ok, status: res.status, payload: payload };
          });
        })
        .then(function (r) {
          if (!r.ok || !r.payload) {
            self.busy = false;
            self.showError();
            return;
          }
          // User-Bubble: server-gerendertes, autoescaped Fragment.
          if (r.payload.bubble_html) {
            self.appendHtml(r.payload.bubble_html);
          }
          // Assistant-Bubble client-seitig anlegen, dann streamen.
          var bubble = self.appendAssistantBubble();
          self.scrollToBottom();
          self.connect(r.payload.stream_url || cfg.streamUrl, bubble);
        })
        .catch(function () {
          self.busy = false;
          self.showError();
        });
    },

    connect: function (url, bubble) {
      var self = this;
      this.closeStream();
      var es = new EventSource(url, { withCredentials: true });
      this.eventSource = es;

      es.onmessage = function (ev) {
        // Default-Event = Token-Delta (Backend `_sse_payload("message", delta)`).
        // Erstes Delta: Typing-Dots wegraeumen, dann reiner Text-Append.
        // NIEMALS innerHTML — kein XSS-Sink.
        if (!bubble._streamStarted) {
          bubble._streamStarted = true;
          bubble.textContent = '';
          bubble.classList.remove('sd-msg__bubble--typing');
        }
        bubble.textContent += ev.data;
        self.scrollToBottom();
      };

      es.addEventListener('done', function () {
        self.finishStream(bubble);
      });

      es.addEventListener('error', function (ev) {
        // EventSource feuert `error` auch beim Verbindungsende. CLOSED = sauber.
        if (es.readyState === EventSource.CLOSED) {
          self.finishStream(bubble);
          return;
        }
        self.failStream(bubble);
        void ev;
      });

      es.onerror = function () {
        if (es.readyState === EventSource.CLOSED) {
          self.finishStream(bubble);
        } else {
          self.failStream(bubble);
        }
      };
    },

    finishStream: function (bubble) {
      this.closeStream();
      this.busy = false;
      if (bubble && bubble.classList) {
        bubble.classList.remove('sd-msg__bubble--typing');
        // Falls der Stream nichts geliefert hat: Platzhalter, kein leerer Block.
        if (!bubble._streamStarted || !bubble.textContent) {
          bubble.textContent = '—';
        }
      }
      this.scrollToBottom();
    },

    failStream: function (bubble) {
      this.closeStream();
      this.busy = false;
      if (bubble && bubble.classList) {
        bubble.classList.remove('sd-msg__bubble--typing');
        if (!bubble._streamStarted || !bubble.textContent) {
          bubble.textContent = 'Could not load a response. Please try again.';
        }
      }
    },

    closeStream: function () {
      if (this.eventSource) {
        this.eventSource.close();
        this.eventSource = null;
      }
    },

    newChat: function () {
      var self = this;
      if (this.busy) return;
      this.busy = true;
      this.closeStream();
      fetch(cfg.newChatUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'X-CSRFToken': csrfToken(),
          Accept: 'text/html',
        },
      })
        .then(function () {
          // Thread leeren + Empty-State zurueck (kein Reload noetig).
          if (self.$refs.messages) self.$refs.messages.textContent = '';
          self.empty = true;
          self.draft = '';
          self.busy = false;
          self.$nextTick(function () {
            if (self.$refs.input) self.$refs.input.focus();
          });
        })
        .catch(function () {
          self.busy = false;
          self.showError();
        });
    },

    back: function () {
      this.closeStream();
      if (cfg.backUrl) window.location.assign(cfg.backUrl);
    },

    // ── DOM-Helfer (Single-Source-Bubble-Struktur gespiegelt) ──────────

    appendHtml: function (html) {
      var box = this.$refs.messages;
      if (box) box.insertAdjacentHTML('beforeend', html);
    },

    appendAssistantBubble: function () {
      // Baut die Assistant-Bubble mit demselben Klassen-/ID-Schema wie das
      // Single-Source-Partial `_partials/group_chat_message.html`:
      //   <div class="sd-msg sd-msg--assistant" id="chat-msg-stream"
      //        data-msg-role="assistant" data-test="chat-msg">
      //     <span class="sd-msg__tag">AI</span>
      //     <div class="sd-msg__bubble" data-msg-bubble>…</div>
      //   </div>
      // Zusaetzlich `sd-msg__bubble--typing` + Typing-Dots bis das erste Delta
      // kommt; der erste Delta-`textContent`-Setter ersetzt die Dots sauber.
      var box = this.$refs.messages;
      if (!box) return null;
      var wrap = document.createElement('div');
      wrap.className = 'sd-msg sd-msg--assistant';
      wrap.id = 'chat-msg-stream';
      wrap.setAttribute('data-msg-role', 'assistant');
      wrap.setAttribute('data-test', 'chat-msg');
      var tag = document.createElement('span');
      tag.className = 'sd-msg__tag';
      tag.textContent = 'AI';
      var bubble = document.createElement('div');
      bubble.className = 'sd-msg__bubble sd-msg__bubble--typing';
      bubble.setAttribute('data-msg-bubble', '');
      var typing = document.createElement('span');
      typing.className = 'sd-chat-typing';
      typing.setAttribute('aria-label', 'AI is typing');
      // Statisches, lokal kontrolliertes Markup (kein User-/LLM-Input).
      typing.appendChild(this._typingDot());
      typing.appendChild(this._typingDot());
      typing.appendChild(this._typingDot());
      bubble.appendChild(typing);
      wrap.appendChild(tag);
      wrap.appendChild(bubble);
      box.appendChild(wrap);
      return bubble;
    },

    _typingDot: function () {
      var d = document.createElement('span');
      d.className = 'sd-chat-typing__dot';
      return d;
    },

    showError: function () {
      // Generischer Fehler — nie Provider-Details leaken.
      var box = this.$refs.messages;
      if (!box) return;
      var err = document.createElement('div');
      err.className = 'sd-chat__error';
      err.setAttribute('data-test', 'group-chat-error');
      err.textContent = 'Could not load a response. Please try again.';
      box.appendChild(err);
      this.scrollToBottom();
    },

    scrollToBottom: function () {
      var thread = this.$refs.thread;
      if (thread) thread.scrollTop = thread.scrollHeight;
    },
  };
}

if (typeof window !== 'undefined') {
  if (window.Alpine) {
    window.Alpine.data('groupChat', groupChat);
  } else {
    document.addEventListener('alpine:init', function () {
      if (window.Alpine) window.Alpine.data('groupChat', groupChat);
    });
  }
}

export { groupChat };
