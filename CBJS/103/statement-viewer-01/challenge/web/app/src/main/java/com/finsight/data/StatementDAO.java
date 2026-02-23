package com.finsight.data;

import com.finsight.model.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class StatementDAO {

    private static final Map<String, List<Statement>> USER_STATEMENTS = new HashMap<>();

    static {
        List<Statement> defaultStatements = new ArrayList<>();
        defaultStatements.add(new Statement("January 2024",
                "2460d5ca8a01fa885703e5cb32644b24/46d41a2a-c2aa-4d85-aa73-f5f68f92c55c.pdf"));
        defaultStatements.add(new Statement("February 2024",
                "2460d5ca8a01fa885703e5cb32644b24/59d75481-4b17-4b3e-a199-2d5a116cbfb7.pdf"));
        defaultStatements.add(new Statement("March 2024",
                "2460d5ca8a01fa885703e5cb32644b24/69ab5f41-9d0a-4d2d-81c8-b23786af4fd1.pdf"));
        defaultStatements.add(new Statement("April 2024",
                "2460d5ca8a01fa885703e5cb32644b24/f6c275ce-8f2a-4969-a50d-40f1e3bd29d2.pdf"));

        USER_STATEMENTS.put("2460d5ca8a01fa885703e5cb32644b24", defaultStatements);
    }

    public static List<Statement> getStatementsByUserId(String userId) {
        return USER_STATEMENTS.getOrDefault(userId, new ArrayList<>());
    }

    public static boolean hasStatements(String userId) {
        return USER_STATEMENTS.containsKey(userId);
    }

    public static void addStatement(String userId, Statement statement) {
        USER_STATEMENTS.computeIfAbsent(userId, k -> new ArrayList<>()).add(statement);
    }
}
