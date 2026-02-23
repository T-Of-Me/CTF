package com.finsight.util;

import java.io.File;
import java.io.IOException;
import javax.servlet.ServletContext;
import org.apache.commons.io.FileUtils;

public class FileConfig {

    private static final String UPLOAD_DIR = "WEB-INF/statements";

    public static String getBasePath(ServletContext context) {
        return context.getRealPath("");
    }

    public static String getUploadPath(ServletContext context) {
        return getBasePath(context) + File.separator + UPLOAD_DIR;
    }

    public static String getUserUploadPath(ServletContext context, String userId) {
        return getUploadPath(context) + File.separator + userId;
    }

    public static String getFilePath(ServletContext context, String relativePath) {
        return getBasePath(context) + File.separator + relativePath;
    }

    public static void ensureDirectoryExists(String path) {
        File dir = new File(path);
        try {
            FileUtils.forceMkdir(dir);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create directory: " + path, e);
        }
    }
}
