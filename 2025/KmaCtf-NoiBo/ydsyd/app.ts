import { serve } from "bun";
import { SignJWT, jwtVerify } from "jose";

const JWT_SECRET = "<It's a secret, but I trust you'll figure it out>";
const secretKey = new TextEncoder().encode(JWT_SECRET);

const flag = "KMACTF{hehe}";

function getFlagGetter() {
    return function () {
        return flag;
    };
}
const flagGetter = getFlagGetter();

const users = {
    alice: { configProto: {}, config: Object.create({}), isAdmin: false },
    bob: { configProto: {}, config: Object.create({}), isAdmin: false },
    admin: { configProto: {}, config: Object.create({}), isAdmin: true },
};

const safeProps = new Set(["name", "user"]);

function sandboxTemplate(template: string, context: any) {
    const proxy = new Proxy(context, {
        get(target, prop) {
            if (safeProps.has(prop as string)) {
                return Reflect.get(target, prop);
            }
            throw new Error("Access denied to property: " + prop.toString());
        },
    });
    return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
        try {
            const val = (proxy as any)[key];
            if (typeof val === "string" || typeof val === "number") return val;
        } catch { }
        return "";
    });
}

function merge(target: any, source: any) {
    for (const key in source) {
        if (key === "template" || key === "user") continue;
        if (
            source[key] &&
            typeof source[key] === "object" &&
            target[key] &&
            typeof target[key] === "object"
        ) {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

async function authenticate(request: Request) {
    const authHeader = request.headers.get("authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.slice(7);
    try {
        const { payload } = await jwtVerify(token, secretKey, {
            algorithms: ["HS256"],
        });
        if (payload && typeof payload.user === "string" && users[payload.user]) {
            return { username: payload.user as string, isAdmin: payload.isAdmin === true };
        }
    } catch { }
    return null;
}

async function generateToken(username: string, isAdmin = false) {
    return await new SignJWT({ user: username, isAdmin })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(secretKey);
}

serve({
    async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === "/login" && request.method === "POST") {
            try {
                const body = await request.json();
                const user = body.user;
                if (!user || !users[user]) {
                    return new Response("User not found", { status: 404 });
                }
                const token = await generateToken(user, users[user].isAdmin);
                return new Response(JSON.stringify({ token }), {
                    status: 200,
                    headers: { "Content-Type": "application/json" },
                });
            } catch {
                return new Response("Invalid JSON", { status: 400 });
            }
        }
        const auth = await authenticate(request);
        if (!auth) return new Response("Unauthorized. Use POST /login then POST /annyeong with Bearer token", { status: 401 });
        const username = auth.username;
        const isAdmin = auth.isAdmin;
        const userInfo = users[username];
        if (!Object.getPrototypeOf(userInfo.config)) {
            Object.setPrototypeOf(userInfo.config, userInfo.configProto);
            if (!userInfo.config.user) userInfo.config.user = { name: username };
        }
        if (url.pathname === "/annyeong" && request.method === "POST") {
            try {
                const data = await request.json();
                merge(userInfo.configProto, data);

                if (isAdmin) {
                    return new Response(flagGetter(), { status: 200 });
                }
                const template = "{{name}} says hello";
                const result = sandboxTemplate(template, userInfo.config.user);
                return new Response(result, { status: 200 });
            } catch {
                return new Response("Invalid JSON or sandbox error", { status: 400 });
            }
        }
        return new Response(
            "Unauthorized. Use POST /login then POST /annyeong with Bearer token",
            { status: 401 }
        );
    },
});
