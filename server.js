require("dotenv").config();

const dns = require("dns");
dns.setServers(["1.1.1.1", "8.8.8.8"]);

const express = require("express");
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error("❌ MONGODB_URI missing in .env");
    process.exit(1);
}

const mongoClient = new MongoClient(MONGODB_URI);

let db;

/* ==========================================
   MONGODB
========================================== */

async function connectMongoDB() {
    try {
        await mongoClient.connect();

        db = mongoClient.db("ConnectHub");

        // MongoDB indexes
        await db.collection("users").createIndex(
            { email: 1 },
            { unique: true }
            );


        console.log("🍃 MongoDB connected successfully! ✅");
        console.log("📦 Database: ConnectHub");

    } catch (error) {
        console.error(
            "❌ MongoDB connection failed:",
            error.message
        );

        process.exit(1);
    }
}

const usersCollection = () => db.collection("users");
const postsCollection = () => db.collection("posts");
const messagesCollection = () => db.collection("messages");
const notificationsCollection = () =>
    db.collection("notifications");
const supportCollection = () => db.collection("support");

/* ==========================================
   EXPRESS
========================================== */

app.use(express.json({ limit: "10mb" }));
app.use(express.static(__dirname));

/* ==========================================
   HELPERS
========================================== */

function normalizeUser(user) {
    if (!user) return user;

    if (!Array.isArray(user.followers)) {
        user.followers = [];
    }

    if (!Array.isArray(user.following)) {
        user.following = [];
    }

    if (!Array.isArray(user.interests)) {
        user.interests = [];
    }

    if (!Number.isFinite(Number(user.posts))) {
        user.posts = 0;
    }

    const defaults = {
        follow: true,
        like: true,
        comment: true,
        message: true,
        share: true
    };

    if (
        !user.notificationSettings ||
        typeof user.notificationSettings !== "object"
    ) {
        user.notificationSettings = { ...defaults };
    }

    for (const key of Object.keys(defaults)) {
        if (
            typeof user.notificationSettings[key] !==
            "boolean"
        ) {
            user.notificationSettings[key] =
                defaults[key];
        }
    }

    if (typeof user.darkMode !== "boolean") {
        user.darkMode = false;
    }

    if (!user.role) {
        user.role = "user";
    }

    return user;
}

function publicUser(user) {
    if (!user) return null;

    normalizeUser(user);

    return {
        id: Number(user.id),
        name: user.name || "",
        email: user.email || "",
        age: user.age,
        bio: user.bio || "",
        interests: user.interests,
        profilePhoto: user.profilePhoto || "",
        followers: user.followers.length,
        following: user.following.length,
        posts: Number(user.posts) || 0,
        createdAt: user.createdAt,
        notificationSettings:
            user.notificationSettings,
        darkMode: user.darkMode,
        role: user.role || "user"
    };
}

function publicUserWithoutPrivateSettings(user) {
    const result = publicUser(user);

    if (!result) return null;

    delete result.notificationSettings;
    delete result.darkMode;
    delete result.role;

    return result;
}

/* ==========================================
   USER DATABASE HELPERS
========================================== */

async function getUsers() {
    return await usersCollection()
        .find({})
        .sort({ id: 1 })
        .toArray();
}

async function findUserById(id) {
    return await usersCollection().findOne({
        id: Number(id)
    });
}

async function findUserByEmail(email) {
    return await usersCollection().findOne({
        email: String(email)
            .trim()
            .toLowerCase()
    });
}

async function saveUser(user) {
    normalizeUser(user);

    await usersCollection().updateOne(
        { id: Number(user.id) },
        {
            $set: {
                ...user,
                id: Number(user.id)
            }
        },
        { upsert: true }
    );

    return user;
}

/* ==========================================
   POSTS HELPERS
========================================== */

async function getPosts() {
    return await postsCollection()
        .find({})
        .sort({ id: 1 })
        .toArray();
}

async function savePost(post) {
    await postsCollection().updateOne(
        { id: Number(post.id) },
        {
            $set: {
                ...post,
                id: Number(post.id)
            }
        },
        { upsert: true }
    );

    return post;
}

/* ==========================================
   MESSAGES HELPERS
========================================== */

async function getMessages() {
    return await messagesCollection()
        .find({})
        .sort({ id: 1 })
        .toArray();
}

async function saveMessage(message) {
    await messagesCollection().updateOne(
        { id: Number(message.id) },
        {
            $set: {
                ...message,
                id: Number(message.id)
            }
        },
        { upsert: true }
    );

    return message;
}

/* ==========================================
   NOTIFICATION HELPERS
========================================== */

async function getNotifications() {
    return await notificationsCollection()
        .find({})
        .sort({ createdAt: -1 })
        .toArray();
}

async function saveNotification(notification) {
    await notificationsCollection().updateOne(
        { id: Number(notification.id) },
        {
            $set: {
                ...notification,
                id: Number(notification.id)
            }
        },
        { upsert: true }
    );

    return notification;
}

async function addNotification(
    toUserId,
    fromUserId,
    type,
    text,
    extra = {}
) {
    if (
        !toUserId ||
        !fromUserId ||
        String(toUserId) === String(fromUserId)
    ) {
        return;
    }

    const target = await findUserById(toUserId);

    if (!target) return;

    normalizeUser(target);

    if (
        target.notificationSettings[type] === false
    ) {
        return;
    }

    const notification = {
        id:
            Date.now() +
            Math.floor(Math.random() * 1000),

        toUserId: Number(toUserId),
        fromUserId: Number(fromUserId),
        type,
        text,
        read: false,
        createdAt: new Date().toISOString(),

        ...extra
    };

    await saveNotification(notification);
}

/* ==========================================
   SUPPORT HELPERS
========================================== */

async function getSupportRequests() {
    return await supportCollection()
        .find({})
        .sort({ id: -1 })
        .toArray();
}

/* ==========================================
   ADMIN SECURITY
========================================== */

async function requireAdmin(req, res, next) {
    try {
        const userId = Number(
            req.headers["x-user-id"] ||
            req.body?.userId ||
            req.query?.userId
        );

        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "Admin login required."
            });
        }

        const user = await findUserById(userId);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User not found."
            });
        }

        if (user.role !== "admin") {
            return res.status(403).json({
                success: false,
                message:
                    "Access denied. Admin only."
            });
        }

        req.adminUser = user;

        next();

    } catch (error) {
        console.error(
            "Admin security error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to verify admin access."
        });
    }
}

/* ==========================================
   STATUS
========================================== */

app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message:
            "ConnectHub backend is working! 🚀",
        database: "MongoDB",
        databaseName: "ConnectHub"
    });
});

/* ==========================================
   SIGNUP
========================================== */

app.post("/api/signup", async (req, res) => {
    try {
        const {
            name,
            email,
            password,
            age,
            interests
        } = req.body;

        if (
            !name ||
            !email ||
            !password ||
            !age
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Please fill all required fields."
            });
        }

        if (String(password).length < 6) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must be at least 6 characters."
            });
        }

        const normalizedEmail =
            String(email)
                .trim()
                .toLowerCase();

        const existing =
            await findUserByEmail(
                normalizedEmail
            );

        if (existing) {
            return res.status(409).json({
                success: false,
                message:
                    "An account with this email already exists."
            });
        }

        const newUser = {
            id: Date.now(),

            name: String(name).trim(),

            email: normalizedEmail,

            password:
                await bcrypt.hash(
                    String(password),
                    12
                ),

            age: Number(age),

            interests:
                Array.isArray(interests)
                    ? interests
                    : [],

            bio: "",

            profilePhoto: "",

            followers: [],

            following: [],

            posts: 0,

            notificationSettings: {
                follow: true,
                like: true,
                comment: true,
                message: true,
                share: true
            },

            darkMode: false,

            role: "user",

            createdAt:
                new Date().toISOString()
        };

        await saveUser(newUser);

        res.status(201).json({
            success: true,
            message:
                "Account created successfully! 🎉",
            user: publicUser(newUser)
        });

    } catch (error) {
        console.error(
            "Signup error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to create account."
        });
    }
});

/* ==========================================
   LOGIN
========================================== */

app.post("/api/login", async (req, res) => {
    try {
        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message:
                    "Email and password are required."
            });
        }

        const user =
            await findUserByEmail(email);

        if (!user || !user.password) {
            return res.status(401).json({
                success: false,
                message:
                    "Invalid email or password."
            });
        }

        const correct =
            await bcrypt.compare(
                String(password),
                user.password
            );

        if (!correct) {
            return res.status(401).json({
                success: false,
                message:
                    "Invalid email or password."
            });
        }

        normalizeUser(user);

        await saveUser(user);

        res.json({
            success: true,
            message:
                "Login successful! 🎉",
            user: publicUser(user)
        });

    } catch (error) {
        console.error(
            "Login error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to login."
        });
    }
});

/* ==========================================
   PROFILE
========================================== */

async function updateProfileForUser(
    userId,
    body
) {
    const user =
        await findUserById(userId);

    if (!user) {
        return {
            error: "User not found."
        };
    }

    if (body.name !== undefined) {
        const name =
            String(body.name).trim();

        if (!name) {
            return {
                error: "Name is required."
            };
        }

        user.name = name;
    }

    if (body.email !== undefined) {
        const email =
            String(body.email)
                .trim()
                .toLowerCase();

        if (!email) {
            return {
                error: "Email is required."
            };
        }

        const duplicate =
            await usersCollection().findOne({
                email,
                id: {
                    $ne: Number(user.id)
                }
            });

        if (duplicate) {
            return {
                error:
                    "Email is already in use."
            };
        }

        user.email = email;
    }

    if (
        body.age !== undefined &&
        body.age !== ""
    ) {
        user.age = Number(body.age);
    }

    if (body.bio !== undefined) {
        user.bio =
            String(body.bio).trim();
    }

    if (body.interests !== undefined) {
        user.interests =
            Array.isArray(body.interests)
                ? body.interests
                    .map(x =>
                        String(x).trim()
                    )
                    .filter(Boolean)
                : String(body.interests)
                    .split(",")
                    .map(x =>
                        x.trim()
                    )
                    .filter(Boolean);
    }

    if (
        body.profilePhoto !== undefined
    ) {
        user.profilePhoto =
            String(body.profilePhoto);
    }

    normalizeUser(user);

    await saveUser(user);

    return {
        user: publicUser(user)
    };
}

app.put("/api/profile", async (req, res) => {
    try {
        const userId =
            req.body?.userId;

        let user;

        if (userId) {
            user =
                await findUserById(userId);
        } else {
            const email =
                String(
                    req.body?.email || ""
                )
                    .trim()
                    .toLowerCase();

            if (!email) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Email or user ID is required."
                });
            }

            user =
                await findUserByEmail(
                    email
                );
        }

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        const result =
            await updateProfileForUser(
                user.id,
                req.body
            );

        if (result.error) {
            return res.status(400).json({
                success: false,
                message: result.error
            });
        }

        res.json({
            success: true,
            message:
                "Profile updated successfully! 🎉",
            user: result.user
        });

    } catch (error) {
        console.error(
            "Profile update error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to update profile."
        });
    }
});

app.put(
    "/api/users/:userId",
    async (req, res) => {
        try {
            const result =
                await updateProfileForUser(
                    req.params.userId,
                    req.body
                );

            if (result.error) {
                return res.status(400).json({
                    success: false,
                    message: result.error
                });
            }

            res.json({
                success: true,
                message:
                    "Profile updated successfully! 🎉",
                user: result.user
            });

        } catch (error) {
            console.error(
                "User profile update error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to update profile."
            });
        }
    }
);

/* ==========================================
   POSTS
========================================== */

app.get("/api/posts", async (req, res) => {
    try {
        const posts =
            await getPosts();

        posts.reverse();

        res.json({
            success: true,
            posts
        });

    } catch (error) {
        console.error(
            "Load posts error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to load posts."
        });
    }
});

app.post("/api/posts", async (req, res) => {
    try {
        const {
            userId,
            userName,
            content
        } = req.body;

        if (
            !userId ||
            !userName ||
            !content ||
            !String(content).trim()
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Post content is required."
            });
        }

        const user =
            await findUserById(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        const post = {
            id: Date.now(),

            userId: Number(userId),

            userName:
                String(userName).trim(),

            content:
                String(content).trim(),

            likes: 0,

            likedBy: [],

            comments: [],

            shares: 0,

            createdAt:
                new Date().toISOString()
        };

        await savePost(post);

        normalizeUser(user);

        user.posts =
            (Number(user.posts) || 0) + 1;

        await saveUser(user);

        res.status(201).json({
            success: true,
            message:
                "Post created successfully! 🎉",
            post
        });

    } catch (error) {
        console.error(
            "Create post error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to create post."
        });
    }
});

/* ==========================================
   LIKE
========================================== */

app.post(
    "/api/posts/:postId/like",
    async (req, res) => {
        try {
            const postId =
                Number(req.params.postId);

            const uid =
                Number(req.body?.userId);

            if (!uid) {
                return res.status(400).json({
                    success: false,
                    message:
                        "User ID is required."
                });
            }

            const user =
                await findUserById(uid);

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Login required."
                });
            }

            const post =
                await postsCollection().findOne({
                    id: postId
                });

            if (!post) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Post not found."
                });
            }

            if (!Array.isArray(post.likedBy)) {
                post.likedBy = [];
            }

            const index =
                post.likedBy.findIndex(
                    id => Number(id) === uid
                );

            let liked;

            if (index >= 0) {
                post.likedBy.splice(
                    index,
                    1
                );

                liked = false;

            } else {
                post.likedBy.push(uid);

                liked = true;

                await addNotification(
                    post.userId,
                    uid,
                    "like",
                    "liked your post",
                    { postId }
                );
            }

            post.likes =
                post.likedBy.length;

            await savePost(post);

            res.json({
                success: true,
                likes: post.likes,
                liked
            });

        } catch (error) {
            console.error(
                "Like error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to like post."
            });
        }
    }
);

/* ==========================================
   COMMENTS
========================================== */

app.post(
    "/api/posts/:postId/comments",
    async (req, res) => {
        try {
            const postId =
                Number(req.params.postId);

            const {
                userId,
                userName,
                text
            } = req.body;

            if (
                !userId ||
                !userName ||
                !text ||
                !String(text).trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Comment information is required."
                });
            }

            const user =
                await findUserById(userId);

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Login required."
                });
            }

            const post =
                await postsCollection().findOne({
                    id: postId
                });

            if (!post) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Post not found."
                });
            }

            if (!Array.isArray(post.comments)) {
                post.comments = [];
            }

            const comment = {
                id: Date.now(),

                userId: Number(userId),

                userName:
                    String(userName).trim(),

                text:
                    String(text).trim(),

                createdAt:
                    new Date().toISOString()
            };

            post.comments.push(comment);

            await savePost(post);

            await addNotification(
                post.userId,
                userId,
                "comment",
                "commented on your post",
                {
                    postId,
                    commentId: comment.id
                }
            );

            res.status(201).json({
                success: true,
                comment
            });

        } catch (error) {
            console.error(
                "Comment error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to add comment."
            });
        }
    }
);

/* ==========================================
   SHARE
========================================== */

app.post(
    "/api/posts/:postId/share",
    async (req, res) => {
        try {
            const postId =
                Number(req.params.postId);

            const userId =
                Number(req.body?.userId);

            const post =
                await postsCollection().findOne({
                    id: postId
                });

            if (!post) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Post not found."
                });
            }

            if (
                userId &&
                !(await findUserById(userId))
            ) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Login required."
                });
            }

            post.shares =
                (Number(post.shares) || 0) + 1;

            await savePost(post);

            if (userId) {
                await addNotification(
                    post.userId,
                    userId,
                    "share",
                    "shared your post",
                    { postId }
                );
            }

            res.json({
                success: true,
                shares: post.shares
            });

        } catch (error) {
            console.error(
                "Share error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to share post."
            });
        }
    }
);

/* ==========================================
   DISCOVER
========================================== */

app.get("/api/users", async (req, res) => {
    try {
        const q =
            String(
                req.query.search || ""
            )
                .trim()
                .toLowerCase();

        const currentUserId =
            req.query.currentUserId;

        const users =
            await getUsers();

        const result =
            users
                .filter(user => {
                    if (!q) return true;

                    return (
                        String(
                            user.name || ""
                        )
                            .toLowerCase()
                            .includes(q) ||

                        String(
                            user.email || ""
                        )
                            .toLowerCase()
                            .includes(q) ||

                        (
                            Array.isArray(
                                user.interests
                            )
                                ? user.interests.join(" ")
                                : ""
                        )
                            .toLowerCase()
                            .includes(q)
                    );
                })

                .filter(
                    user =>
                        String(user.id) !==
                        String(currentUserId)
                )

                .map(user => {
                    normalizeUser(user);

                    return {
                        ...publicUserWithoutPrivateSettings(
                            user
                        ),

                        isFollowing:
                            currentUserId
                                ? user.followers.includes(
                                    Number(
                                        currentUserId
                                    )
                                )
                                : false
                    };
                });

        res.json({
            success: true,
            users: result
        });

    } catch (error) {
        console.error(
            "Users search error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to load users."
        });
    }
});

/* ==========================================
   USER PROFILE
========================================== */

app.get(
    "/api/users/:userId",
    async (req, res) => {
        try {
            const user =
                await findUserById(
                    req.params.userId
                );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            normalizeUser(user);

            const currentUserId =
                req.query.currentUserId;

            const posts =
                await postsCollection()
                    .find({
                        userId: Number(user.id)
                    })
                    .sort({ id: -1 })
                    .limit(10)
                    .toArray();

            res.json({
                success: true,

                user: {
                    ...publicUser(user),

                    isFollowing:
                        currentUserId
                            ? user.followers.includes(
                                Number(
                                    currentUserId
                                )
                            )
                            : false,

                    recentPosts: posts
                }
            });

        } catch (error) {
            console.error(
                "Profile load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load profile."
            });
        }
    }
);

/* ==========================================
   FOLLOW
========================================== */

app.post(
    "/api/users/:userId/follow",
    async (req, res) => {
        try {
            const targetId =
                Number(req.params.userId);

            const followerId =
                Number(req.body?.userId);

            if (
                !followerId ||
                !targetId ||
                followerId === targetId
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid follow request."
                });
            }

            const follower =
                await findUserById(
                    followerId
                );

            const target =
                await findUserById(
                    targetId
                );

            if (!follower || !target) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            normalizeUser(follower);
            normalizeUser(target);

            const alreadyFollowing =
                target.followers.includes(
                    followerId
                );

            if (!alreadyFollowing) {
                target.followers.push(
                    followerId
                );

                if (
                    !follower.following.includes(
                        targetId
                    )
                ) {
                    follower.following.push(
                        targetId
                    );
                }

                await addNotification(
                    targetId,
                    followerId,
                    "follow",
                    "started following you"
                );
            }

            await saveUser(follower);
            await saveUser(target);

            res.json({
                success: true,
                following:
                    follower.following.length,
                followers:
                    target.followers.length,
                isFollowing: true
            });

        } catch (error) {
            console.error(
                "Follow error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to follow user."
            });
        }
    }
);

/* ==========================================
   UNFOLLOW
========================================== */

app.post(
    "/api/users/:userId/unfollow",
    async (req, res) => {
        try {
            const targetId =
                Number(req.params.userId);

            const followerId =
                Number(req.body?.userId);

            if (
                !followerId ||
                !targetId ||
                followerId === targetId
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid unfollow request."
                });
            }

            const follower =
                await findUserById(
                    followerId
                );

            const target =
                await findUserById(
                    targetId
                );

            if (!follower || !target) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            normalizeUser(follower);
            normalizeUser(target);

            follower.following =
                follower.following.filter(
                    id =>
                        Number(id) !==
                        targetId
                );

            target.followers =
                target.followers.filter(
                    id =>
                        Number(id) !==
                        followerId
                );

            await saveUser(follower);
            await saveUser(target);

            res.json({
                success: true,
                following:
                    follower.following.length,
                followers:
                    target.followers.length,
                isFollowing: false
            });

        } catch (error) {
            console.error(
                "Unfollow error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to unfollow user."
            });
        }
    }
);

/* ==========================================
   FOLLOWERS / FOLLOWING
========================================== */

async function getConnectionList(
    req,
    res,
    type
) {
    try {
        const user =
            await findUserById(
                req.params.userId
            );

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        normalizeUser(user);

        const ids =
            type === "followers"
                ? user.followers
                : user.following;

        const result = [];

        for (const id of ids) {
            const found =
                await findUserById(id);

            if (found) {
                result.push(
                    publicUserWithoutPrivateSettings(
                        found
                    )
                );
            }
        }

        res.json({
            success: true,
            users: result
        });

    } catch (error) {
        console.error(
            `${type} error:`,
            error
        );

        res.status(500).json({
            success: false,
            message:
                `Unable to load ${type}.`
        });
    }
}

app.get(
    "/api/users/:userId/followers",
    async (req, res) =>
        getConnectionList(
            req,
            res,
            "followers"
        )
);

app.get(
    "/api/users/:userId/following",
    async (req, res) =>
        getConnectionList(
            req,
            res,
            "following"
        )
);

/* ==========================================
   MESSAGES
========================================== */

app.get(
    "/api/messages/:userId/:otherUserId",
    async (req, res) => {
        try {
            const a =
                Number(req.params.userId);

            const b =
                Number(req.params.otherUserId);

            if (!a || !b) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID."
                });
            }

            const userA =
                await findUserById(a);

            const userB =
                await findUserById(b);

            if (!userA || !userB) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            await messagesCollection().updateMany(
                {
                    senderId: b,
                    receiverId: a,
                    read: { $ne: true }
                },
                {
                    $set: {
                        read: true
                    }
                }
            );

            const chatMessages =
                await messagesCollection()
                    .find({
                        $or: [
                            {
                                senderId: a,
                                receiverId: b
                            },
                            {
                                senderId: b,
                                receiverId: a
                            }
                        ]
                    })
                    .sort({ id: 1 })
                    .toArray();

            res.json({
                success: true,
                messages: chatMessages
            });

        } catch (error) {
            console.error(
                "Load messages error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load messages."
            });
        }
    }
);

/* ==========================================
   SEND MESSAGE
========================================== */

app.post(
    "/api/messages",
    async (req, res) => {
        try {
            const {
                senderId,
                receiverId,
                text
            } = req.body;

            if (
                !senderId ||
                !receiverId ||
                !text ||
                !String(text).trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Message information is required."
                });
            }

            if (
                Number(senderId) ===
                Number(receiverId)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "You cannot message yourself."
                });
            }

            const sender =
                await findUserById(
                    senderId
                );

            const receiver =
                await findUserById(
                    receiverId
                );

            if (!sender || !receiver) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            const message = {
                id: Date.now(),

                senderId:
                    Number(senderId),

                receiverId:
                    Number(receiverId),

                text:
                    String(text).trim(),

                read: false,

                createdAt:
                    new Date().toISOString()
            };

            await saveMessage(message);

            await addNotification(
                receiverId,
                senderId,
                "message",
                "sent you a message",
                {
                    messageId:
                        message.id
                }
            );

            res.status(201).json({
                success: true,
                message
            });

        } catch (error) {
            console.error(
                "Message error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to send message."
            });
        }
    }
);

/* ==========================================
   UNREAD MESSAGE COUNTS
========================================== */

app.get(
    "/api/unread-messages/:userId",
    async (req, res) => {
        try {
            const userId =
                Number(req.params.userId);

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID."
                });
            }

            const user =
                await findUserById(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            const messages =
                await messagesCollection()
                    .find({
                        receiverId: userId,
                        read: { $ne: true }
                    })
                    .toArray();

            const counts = {};

            messages.forEach(message => {
                const senderId =
                    Number(message.senderId);

                counts[senderId] =
                    (counts[senderId] || 0) + 1;
            });

            res.json({
                success: true,
                counts
            });

        } catch (error) {
            console.error(
                "Unread message error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load unread message counts."
            });
        }
    }
);

/* ==========================================
   TOTAL UNREAD COUNTS
========================================== */

app.get(
    "/api/unread-counts/:userId",
    async (req, res) => {
        try {
            const userId =
                Number(req.params.userId);

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID."
                });
            }

            const user =
                await findUserById(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            const unreadMessages =
                await messagesCollection()
                    .countDocuments({
                        receiverId: userId,
                        read: { $ne: true }
                    });

            const unreadNotifications =
                await notificationsCollection()
                    .countDocuments({
                        toUserId: userId,
                        read: { $ne: true }
                    });

            res.json({
                success: true,
                messages:
                    unreadMessages,
                notifications:
                    unreadNotifications,
                total:
                    unreadMessages +
                    unreadNotifications
            });

        } catch (error) {
            console.error(
                "Unread count error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load unread counts."
            });
        }
    }
);

/* ==========================================
   NOTIFICATIONS
========================================== */

app.get(
    "/api/notifications/:userId",
    async (req, res) => {
        try {
            const userId =
                Number(req.params.userId);

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID."
                });
            }

            const user =
                await findUserById(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            const notifications =
                await notificationsCollection()
                    .find({
                        toUserId: userId
                    })
                    .sort({
                        createdAt: -1
                    })
                    .toArray();

            const result = [];

            for (
                const notification
                of notifications
            ) {
                const fromUser =
                    await findUserById(
                        notification.fromUserId
                    );

                result.push({
                    ...notification,

                    fromUser:
                        fromUser
                            ? publicUserWithoutPrivateSettings(
                                fromUser
                            )
                            : null
                });
            }

            res.json({
                success: true,
                notifications: result
            });

        } catch (error) {
            console.error(
                "Notification load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load notifications."
            });
        }
    }
);

/* ==========================================
   MARK NOTIFICATION READ
========================================== */

app.put(
    "/api/notifications/:notificationId/read",
    async (req, res) => {
        try {
            const notificationId =
                Number(
                    req.params.notificationId
                );

            const userId =
                Number(req.body?.userId);

            if (
                !notificationId ||
                !userId
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Notification ID and user ID are required."
                });
            }

            const result =
                await notificationsCollection()
                    .updateOne(
                        {
                            id: notificationId,
                            toUserId: userId
                        },
                        {
                            $set: {
                                read: true
                            }
                        }
                    );

            if (!result.matchedCount) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Notification not found."
                });
            }

            res.json({
                success: true,
                message:
                    "Notification marked as read."
            });

        } catch (error) {
            console.error(
                "Notification read error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to mark notification as read."
            });
        }
    }
);

/* ==========================================
   MARK ALL READ
========================================== */

app.put(
    "/api/notifications/:userId/read-all",
    async (req, res) => {
        try {
            const userId =
                Number(req.params.userId);

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID."
                });
            }

            const user =
                await findUserById(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            const result =
                await notificationsCollection()
                    .updateMany(
                        {
                            toUserId: userId,
                            read: { $ne: true }
                        },
                        {
                            $set: {
                                read: true
                            }
                        }
                    );

            res.json({
                success: true,
                message:
                    "All notifications marked as read.",
                updated:
                    result.modifiedCount
            });

        } catch (error) {
            console.error(
                "Mark all notifications error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to mark notifications as read."
            });
        }
    }
);

/* ==========================================
   NOTIFICATION SETTINGS
========================================== */

app.get(
    "/api/settings/notifications/:userId",
    async (req, res) => {
        try {
            const user =
                await findUserById(
                    req.params.userId
                );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            normalizeUser(user);

            await saveUser(user);

            res.json({
                success: true,
                settings:
                    user.notificationSettings
            });

        } catch (error) {
            console.error(
                "Notification settings load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load notification settings."
            });
        }
    }
);

app.put(
    "/api/settings/notifications/:userId",
    async (req, res) => {
        try {
            const user =
                await findUserById(
                    req.params.userId
                );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            normalizeUser(user);

            const allowed = [
                "follow",
                "like",
                "comment",
                "message",
                "share"
            ];

            allowed.forEach(key => {
                if (
                    typeof req.body?.[key] ===
                    "boolean"
                ) {
                    user.notificationSettings[
                        key
                    ] = req.body[key];
                }
            });

            await saveUser(user);

            res.json({
                success: true,
                message:
                    "Notification settings saved.",
                settings:
                    user.notificationSettings
            });

        } catch (error) {
            console.error(
                "Notification settings update error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save notification settings."
            });
        }
    }
);

/* ==========================================
   DARK MODE
========================================== */

app.get(
    "/api/settings/appearance/:userId",
    async (req, res) => {
        try {
            const user =
                await findUserById(
                    req.params.userId
                );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            normalizeUser(user);

            res.json({
                success: true,
                darkMode:
                    user.darkMode
            });

        } catch (error) {
            console.error(
                "Appearance load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load appearance."
            });
        }
    }
);

app.put(
    "/api/settings/appearance/:userId",
    async (req, res) => {
        try {
            const user =
                await findUserById(
                    req.params.userId
                );

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            user.darkMode =
                req.body?.darkMode === true;

            await saveUser(user);

            res.json({
                success: true,
                darkMode:
                    user.darkMode
            });

        } catch (error) {
            console.error(
                "Appearance update error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save appearance."
            });
        }
    }
);

/* ==========================================
   CHANGE PASSWORD
========================================== */

async function changePasswordHandler(
    req,
    res
) {
    try {
        const {
            userId,
            currentPassword,
            newPassword
        } = req.body;

        if (
            !userId ||
            !currentPassword ||
            !newPassword
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Enter all password details."
            });
        }

        if (
            String(newPassword).length < 6
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "New password must be at least 6 characters."
            });
        }

        const user =
            await findUserById(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        const correct =
            await bcrypt.compare(
                String(currentPassword),
                user.password
            );

        if (!correct) {
            return res.status(401).json({
                success: false,
                message:
                    "Current password is incorrect."
            });
        }

        user.password =
            await bcrypt.hash(
                String(newPassword),
                12
            );

        await saveUser(user);

        res.json({
            success: true,
            message:
                "Password changed successfully."
        });

    } catch (error) {
        console.error(
            "Password error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to change password."
        });
    }
}

app.put(
    "/api/security/password",
    changePasswordHandler
);

app.put(
    "/api/change-password",
    changePasswordHandler
);

/* ==========================================
   SUPPORT REQUEST
========================================== */

app.post(
    "/api/support",
    async (req, res) => {
        try {
            const {
                userId,
                name,
                email,
                message
            } = req.body;

            if (
                !message ||
                !String(message).trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Please describe your problem."
                });
            }

            const request = {
                id: Date.now(),

                userId:
                    userId
                        ? Number(userId)
                        : null,

                name:
                    String(
                        name ||
                        "Unknown User"
                    ).trim(),

                email:
                    String(email || "")
                        .trim()
                        .toLowerCase(),

                message:
                    String(message).trim(),

                status: "open",

                createdAt:
                    new Date().toISOString()
            };

            await supportCollection().insertOne(
                request
            );

            res.status(201).json({
                success: true,
                message:
                    "Support request submitted successfully! ✅",
                request
            });

        } catch (error) {
            console.error(
                "Support request error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to submit support request."
            });
        }
    }
);

/* ==========================================
   GET SUPPORT
========================================== */

app.get(
    "/api/support",
    async (req, res) => {
        try {
            const requests =
                await getSupportRequests();

            res.json({
                success: true,
                requests
            });

        } catch (error) {
            console.error(
                "Support load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load support requests."
            });
        }
    }
);

/* ==========================================
   UPDATE SUPPORT
========================================== */

app.put(
    "/api/support/:requestId",
    async (req, res) => {
        try {
            const requestId =
                Number(req.params.requestId);

            const status =
                String(
                    req.body?.status || ""
                ).trim();

            const allowedStatuses = [
                "open",
                "pending",
                "resolved"
            ];

            if (
                !allowedStatuses.includes(
                    status
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid support status."
                });
            }

            const request =
                await supportCollection()
                    .findOne({
                        id: requestId
                    });

            if (!request) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Support request not found."
                });
            }

            await supportCollection()
                .updateOne(
                    { id: requestId },
                    {
                        $set: {
                            status
                        }
                    }
                );

            request.status = status;

            res.json({
                success: true,
                message:
                    "Support request updated successfully.",
                request
            });

        } catch (error) {
            console.error(
                "Support update error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to update support request."
            });
        }
    }
);

/* ==========================================
   DELETE SUPPORT
========================================== */

app.delete(
    "/api/support/:requestId",
    async (req, res) => {
        try {
            const requestId =
                Number(req.params.requestId);

            if (!requestId) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid support request ID."
                });
            }

            const result =
                await supportCollection()
                    .deleteOne({
                        id: requestId
                    });

            if (!result.deletedCount) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Support request not found."
                });
            }

            res.json({
                success: true,
                message:
                    "Support request deleted successfully."
            });

        } catch (error) {
            console.error(
                "Support delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete support request."
            });
        }
    }
);

/* ==========================================
   DELETE ACCOUNT
========================================== */

app.delete(
    "/api/users/:userId",
    async (req, res) => {
        try {
            const userId =
                Number(req.params.userId);

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID."
                });
            }

            const user =
                await findUserById(userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }

            /* DELETE USER */

            await usersCollection().deleteOne({
                id: userId
            });

            /* REMOVE FOLLOW REFERENCES */

            await usersCollection().updateMany(
                {},
                {
                    $pull: {
                        followers: userId,
                        following: userId
                    }
                }
            );

            /* DELETE USER POSTS */

            await postsCollection().deleteMany({
                userId
            });

            /* REMOVE LIKES */

            const posts =
                await postsCollection()
                    .find({})
                    .toArray();

            for (const post of posts) {
                let changed = false;

                if (
                    Array.isArray(
                        post.likedBy
                    )
                ) {
                    const oldLength =
                        post.likedBy.length;

                    post.likedBy =
                        post.likedBy.filter(
                            id =>
                                Number(id) !==
                                userId
                        );

                    if (
                        post.likedBy.length !==
                        oldLength
                    ) {
                        changed = true;
                    }

                    post.likes =
                        post.likedBy.length;
                }

                if (
                    Array.isArray(
                        post.comments
                    )
                ) {
                    const oldLength =
                        post.comments.length;

                    post.comments =
                        post.comments.filter(
                            comment =>
                                Number(
                                    comment.userId
                                ) !== userId
                        );

                    if (
                        post.comments.length !==
                        oldLength
                    ) {
                        changed = true;
                    }
                }

                if (changed) {
                    await savePost(post);
                }
            }

            /* DELETE MESSAGES */

            await messagesCollection()
                .deleteMany({
                    $or: [
                        {
                            senderId: userId
                        },
                        {
                            receiverId: userId
                        }
                    ]
                });

            /* DELETE NOTIFICATIONS */

            await notificationsCollection()
                .deleteMany({
                    $or: [
                        {
                            toUserId: userId
                        },
                        {
                            fromUserId: userId
                        }
                    ]
                });

            /* DELETE SUPPORT REQUESTS */

            await supportCollection()
                .deleteMany({
                    userId
                });

            res.json({
                success: true,
                message:
                    "Account and all related data deleted successfully."
            });

        } catch (error) {
            console.error(
                "Delete account error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete account."
            });
        }
    }
);

/* ==========================================
   ADMIN SUPPORT ROUTES
========================================== */

app.get(
    "/api/admin/support",
    requireAdmin,
    async (req, res) => {
        try {
            const requests =
                await getSupportRequests();

            res.json({
                success: true,
                requests
            });

        } catch (error) {
            console.error(
                "Admin support error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load support requests."
            });
        }
    }
);

/* ==========================================
   START SERVER
========================================== */

async function startServer() {
    await connectMongoDB();

    app.listen(PORT, () => {
        console.log("");
        console.log(
            "======================================"
        );
        console.log(
            "🚀 ConnectHub server is running!"
        );
        console.log(
            `🌐 http://localhost:${PORT}`
        );
        console.log(
            "🍃 MongoDB database: ConnectHub"
        );
        console.log(
            "💾 Users, posts, messages, notifications & support are stored in MongoDB."
        );
        console.log(
            "🔐 Security + notification settings + dark mode APIs ready."
        );
        console.log(
            "🛡️ Account deletion cleanup enabled."
        );
        console.log(
            "======================================"
        );
    });
}

startServer();

process.on(
    "SIGINT",
    async () => {
        console.log(
            "\n🛑 Shutting down server..."
        );

        await mongoClient.close();

        process.exit(0);
    }
);