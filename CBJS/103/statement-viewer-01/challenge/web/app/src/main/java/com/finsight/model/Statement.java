package com.finsight.model;

public class Statement {
    private String fileName;
    private String filePath;

    public Statement(String fileName, String filePath) {
        this.fileName = fileName;
        this.filePath = filePath;
    }

    public String getFileName() {
        return fileName;
    }

    public String getFilePath() {
        return filePath;
    }
}
