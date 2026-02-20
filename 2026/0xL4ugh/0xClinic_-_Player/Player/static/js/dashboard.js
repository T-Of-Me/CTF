async function initDashboard() {
  try {
    const resp = await fetch('/api/userdata', { credentials: 'include' });
    if (!resp.ok) return;
    const data = await resp.json();
    const username = data.username || 'User';

    document.getElementById('userName').textContent = username;
    const link = document.getElementById('userLink');
    if (link) link.href = '/profile';

    document.getElementById('dashboardUserName').textContent = username;
    const initial = username.charAt(0).toUpperCase();
    document.getElementById('userAvatar').textContent = initial;
  } catch (e) {
    console.warn('Failed to load user session', e);
  }
}

async function handleSendMessage(event) {
  event.preventDefault();
  
  const messageText = document.getElementById("messageText").value;
  const errorMessage = document.getElementById("messageError");
  const successMessage = document.getElementById("messageSuccess");
  const submitBtn = document.getElementById("sendMessageBtn");
  const btnText = document.getElementById("sendBtnText");
  
  errorMessage.style.display = "none";
  successMessage.style.display = "none";
  
  if (!messageText.trim()) {
    errorMessage.textContent = "Message cannot be empty";
    errorMessage.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  btnText.textContent = "Sending...";
  
  try {
    const response = await fetch("/api/send-message", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        Illness: document.getElementById("illness").value,
        message: messageText
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      successMessage.textContent = "Message sent successfully!";
      successMessage.style.display = "block";
      document.getElementById("messageText").value = "";
      btnText.textContent = "Send message";
      submitBtn.disabled = false;
      
      setTimeout(() => {
        successMessage.style.display = "none";
      }, 3000);
    } else {
      errorMessage.textContent = data.message || "Failed to send message";
      errorMessage.style.display = "block";
      submitBtn.disabled = false;
      btnText.textContent = "Send message";
    }
  } catch (error) {
    errorMessage.textContent = "An error occurred. Please try again.";
    errorMessage.style.display = "block";
    submitBtn.disabled = false;
    btnText.textContent = "Send message";
    console.error("Send message error:", error);
  }
}

initDashboard();
