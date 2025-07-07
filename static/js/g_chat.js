export class ChatApp {
  constructor(socket) {
    this.socket = socket;
    this.messageInput = document.getElementById('message-input');
    this.chatMessages = document.getElementById('chat-messages');
    this.sendButton = document.getElementById('send-button');

    this.sendButton.addEventListener('click', () => this.sendMessage());
    this.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        this.sendMessage();
      }
    });
  }

  sendMessage() {
    const text = this.messageInput.value.trim();
    if (!text) return;

    this.socket.emit('send_message', { message: text });
    this.messageInput.value = '';
  }

  receiveMessage({ username, content, timestamp }) {
    const formattedTime = new Date(timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });

    this.addMessage({ username, content, timestamp: formattedTime });
  }

  addMessage({ username, content, timestamp }) {
    const messageEl = document.createElement('div');
    messageEl.className = 'message';
    messageEl.innerHTML = `
      <div class="message-header">
        <span class="message-username">${this.escapeHTML(username)}</span>
        <span class="message-time">${timestamp}</span>
      </div>
      <div class="message-content">${this.escapeHTML(content)}</div>
    `;
    this.chatMessages.appendChild(messageEl);
    this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
  }

  escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
}
