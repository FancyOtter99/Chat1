const socket = io();

window.onload = () => {
  const room = window.location.pathname.includes('/group/') ?
                window.location.pathname.split('/group/')[1] : 'main';
  socket.emit('join', { room });
};

function sendMessage(room) {
  const msgInput = document.getElementById('msg');
  const message = msgInput.value;
  if (message.trim() !== '') {
    socket.emit('send_message', { room, message });
    msgInput.value = '';
  }
}

socket.on('receive_message', (data) => {
  const messagesDiv = document.getElementById('messages');
  const newMsg = document.createElement('div');
  newMsg.textContent = `${data.username}: ${data.message}`;
  messagesDiv.appendChild(newMsg);
});
