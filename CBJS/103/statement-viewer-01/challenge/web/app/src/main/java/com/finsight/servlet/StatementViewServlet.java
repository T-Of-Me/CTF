package com.finsight.servlet;

import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.RequestDispatcher;

import com.finsight.data.StatementDAO;

public class StatementViewServlet extends HttpServlet {

    private static final Logger logger = Logger.getLogger(StatementViewServlet.class.getName());

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("userId");

        if (userId == null || userId.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing userId parameter");
            return;
        }

        logger.info("Statement view request for user: " + userId);
        request.setAttribute("userId", userId);
        request.setAttribute("statements", StatementDAO.getStatementsByUserId(userId));

        RequestDispatcher dispatcher = request.getRequestDispatcher("/WEB-INF/jsp/statementForm.jsp");
        dispatcher.forward(request, response);
    }
}