package com.finsight.servlet;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import javax.servlet.RequestDispatcher;

import org.apache.commons.io.FilenameUtils;

import com.finsight.data.StatementDAO;
import com.finsight.model.Statement;
import com.finsight.util.FileConfig;

// 1 MB, 10 MB, 50 MB
@MultipartConfig(fileSizeThreshold = 1024 * 1024, maxFileSize = 10 * 1024 * 1024, maxRequestSize = 50 * 1024 * 1024)
public class StatementUploadServlet extends HttpServlet {

    private static final Logger logger = Logger.getLogger(StatementUploadServlet.class.getName());

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("userId");
        request.setAttribute("userId", userId);

        RequestDispatcher dispatcher = request.getRequestDispatcher("/WEB-INF/jsp/uploadForm.jsp");
        dispatcher.forward(request, response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("userId");
        String message = "Please select a file to upload.";
        String messageType = "error";

        try {
            if (userId == null || userId.trim().isEmpty()) {
                message = "User ID is required.";
                forwardWithMessage(request, response, userId, message, "error");
                return;
            }

            Part filePart = request.getPart("file");
            if (filePart == null || filePart.getSize() == 0) {
                forwardWithMessage(request, response, userId, message, messageType);
                return;
            }

            String fileName = null;
            String contentDisp = filePart.getHeader("content-disposition");
            if (contentDisp != null) {
                for (String content : contentDisp.split(";")) {
                    if (content.trim().startsWith("filename")) {
                        fileName = new File(content.substring(content.indexOf('=') + 1)
                                .trim().replace("\"", "")).getName();
                        break;
                    }
                }
            }

            if (fileName == null || fileName.trim().isEmpty()) {
                message = "Invalid file name.";
                forwardWithMessage(request, response, userId, message, messageType);
                return;
            }

            String fileExt = FilenameUtils.getExtension(fileName).toLowerCase();
            if (!("pdf".equals(fileExt) || "txt".equals(fileExt))) {
                message = "Only PDF and TXT files allowed.";
                forwardWithMessage(request, response, userId, message, messageType);
                return;
            }

            if (filePart.getSize() > 10 * 1024 * 1024) {
                message = "File too large (max 10MB).";
                forwardWithMessage(request, response, userId, message, messageType);
                return;
            }

            String uploadPath = FileConfig.getUserUploadPath(getServletContext(), userId.trim());
            FileConfig.ensureDirectoryExists(uploadPath);

            String uniqueName = UUID.randomUUID().toString() + '.' + fileExt;
            filePart.write(uploadPath + File.separator + uniqueName);

            fileName = FilenameUtils.getBaseName(fileName);
            StatementDAO.addStatement(userId.trim(),
                    new Statement(fileName, userId.trim() + "/" + uniqueName));

            message = "Remote file uploaded name: " + uniqueName;
            messageType = "success";

        } catch (Exception e) {
            message = "Upload failed: " + e.getMessage();
            logger.warning("Upload error: " + e.getMessage());
            e.printStackTrace();
        }

        forwardWithMessage(request, response, userId, message, messageType);
    }

    private void forwardWithMessage(HttpServletRequest request, HttpServletResponse response,
            String userId, String message, String messageType)
            throws ServletException, IOException {
        request.setAttribute("userId", userId);
        request.setAttribute("message", message);
        request.setAttribute("messageType", messageType);
        request.getRequestDispatcher("/WEB-INF/jsp/uploadForm.jsp").forward(request, response);
    }
}