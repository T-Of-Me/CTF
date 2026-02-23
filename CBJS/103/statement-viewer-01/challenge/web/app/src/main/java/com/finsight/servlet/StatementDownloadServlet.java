package com.finsight.servlet;

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FileUtils;

import com.finsight.util.FileConfig;

public class StatementDownloadServlet extends HttpServlet {

    private static final Logger logger = Logger.getLogger(StatementDownloadServlet.class.getName());

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String filename = request.getParameter("file");

        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        File file = new File(FileConfig.getUploadPath(getServletContext()), filename);
        logger.info("Download request for file: " + filename + " at path: " + file.getAbsolutePath());

        if (!file.exists() || !file.isFile()) {
            logger.warning("File not found: " + filename + " at path: " + file.getAbsolutePath());
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
            return;
        }

        String extension = filename.toLowerCase();
        String contentType = extension.endsWith(".pdf") ? "application/pdf"
                : extension.endsWith(".txt") ? "text/plain" : "application/octet-stream";
        response.setContentType(contentType);

        String displayName = filename.contains("/") ? filename.substring(filename.lastIndexOf("/") + 1) : filename;
        response.setHeader("Content-Disposition", "attachment; filename=\"" + displayName + "\"");
        response.setHeader("Content-Length", String.valueOf(file.length()));

        try {
            FileUtils.copyFile(file, response.getOutputStream());
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error serving file: " + filename, e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error serving file");
        }
    }
}