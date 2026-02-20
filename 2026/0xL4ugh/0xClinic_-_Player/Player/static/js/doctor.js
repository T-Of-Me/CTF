 

async function handleUpload(event) {
      event.preventDefault();
      
      const fileInput = document.getElementById("document");
      const patientId = document.getElementById("patientId").value;
      const errorMessage = document.getElementById("errorMessage");
      const successMessage = document.getElementById("successMessage");
      const uploadBtn = document.getElementById("uploadBtn");
      const uploadBtnText = document.getElementById("uploadBtnText");

      if (!fileInput.files || fileInput.files.length === 0) {
        errorMessage.textContent = "Please select a file to upload.";
        errorMessage.style.display = "block";
        return;
      }

      const file = fileInput.files[0];
      
      const allowedExtensions = ['.pdf', '.doc', '.docx', '.xlsx', '.xls', '.txt', '.png', '.jpg', '.jpeg'];
      const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
      
      if (!allowedExtensions.includes(fileExtension)) {
        errorMessage.textContent = `Invalid file type. Allowed: ${allowedExtensions.join(', ')}`;
        errorMessage.style.display = "block";
        successMessage.style.display = "none";
        return;
      }

      // Hide previous messages
      errorMessage.style.display = "none";
      successMessage.style.display = "none";

      // Show loading state
      uploadBtn.disabled = true;
      uploadBtnText.textContent = "⏳ Uploading...";

      const formData = new FormData();
      formData.append("file", file);
      if (patientId) {
        formData.append("patient_id", patientId);
      }

      try {
        const response = await fetch("/api/upload-document", {
          method: "POST",
          body: formData
        });

        const data = await response.json();

        if (response.ok) {
          successMessage.textContent = `✅ ${data.message} (${file.name})`;
          successMessage.style.display = "block";
          uploadBtnText.textContent = "📤 Upload Document";
          
          // Reset form
          document.getElementById("uploadForm").reset();
        } else {
          errorMessage.textContent = data.message || "Upload failed. Please try again.";
          errorMessage.style.display = "block";
          uploadBtnText.textContent = "📤 Upload Document";
        }
      } catch (error) {
        errorMessage.textContent = "An error occurred during upload. Please try again.";
        errorMessage.style.display = "block";
        uploadBtnText.textContent = "📤 Upload Document";
        console.error("Upload error:", error);
      } finally {
        uploadBtn.disabled = false;
      }
}

