const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const Stripe = require("stripe");



const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: 'http://localhost:5173', // Replace with the frontend URL
  credentials: true, // Allow credentials (cookies, etc.)
};


// middleware
app.use(cors(corsOptions));
app.use(express.json());

const decodedKey = Buffer.from(process.env.FB_SECRET_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.m8kjtvv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});



// Firebase Admin Token verification
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: Token missing or malformed" });
  }

  const token = authHeader.split(" ")[1];
  
  try {
   
    const decodedToken = await admin.auth().verifyIdToken(token); 
    req.user = decodedToken; 
    next();
  } catch (error) {
    console.error("Token verification failed:", error);
    res.status(403).json({ message: "Forbidden", error: error.message });
  }
};



async function run() {
  try {
    const db = client.db("climatedb");
    const postsCollection = db.collection("posts");
    const commentsCollection = db.collection("comments");
    const usersCollection = db.collection("users");
    const tagsCollection = db.collection("tags");
    const announcementsCollection = db.collection("announcements");


    // Create indexes for better performance
    await commentsCollection.createIndex({ postId: 1 });
    await commentsCollection.createIndex({ createdAt: -1 });

      // Login route
    
      // Admin
const verifyAdmin = async (req, res, next) => {
  const user = await usersCollection.findOne({ _id: req.user.uid });

  if (!user || user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden: Admins only" });
  }

  next();
};
    // User Registration
    app.post("/register", async (req, res) => {
      const { email, name, photoURL, uid } = req.body;

      try {
        // Check if user exists
        const existingUser = await usersCollection.findOne({ _id: uid });
        if (existingUser) {
          return res.status(400).send({ message: "User already exists" });
        }

        // Create new user
        const newUser = {
          _id: uid,
          email,
          name,
          photoURL,
          createdAt: new Date(),
          lastLogin: new Date(),
          isMember: false,
          role: "user",
          preferences: {
            theme: "light",
            notifications: true
          }
        };

        await usersCollection.insertOne(newUser);
        res.send({ success: true, user: newUser });
      } catch (error) {
        res.status(500).send({ message: "Registration failed", error: error.message });
      }
    });

    // User Login
  app.post("/login", async (req, res) => {
  const { idToken, email, name, photoURL, uid } = req.body;
  
  try {
    let decodedToken;
    if (idToken) {
      decodedToken = await admin.auth().verifyIdToken(idToken);
    } else if (uid) {
      decodedToken = { uid };
    } else {
      return res.status(400).send({ message: "Authentication token required" });
    }

    const firebaseUid = decodedToken.uid || uid;

    let user = await usersCollection.findOne({ _id: firebaseUid });

    if (!user) {
      // Create new user
      user = {
        _id: firebaseUid,
        email: email || decodedToken.email,
        name: name || decodedToken.name || (email ? email.split('@')[0] : "Anonymous"),
        photoURL: photoURL || decodedToken.picture || '',
        createdAt: new Date(),
        lastLogin: new Date(),
        isMember: false,
        role: "user"
      };
      await usersCollection.insertOne(user);
    } else {
      // Update lastLogin and adjust role based on isMember
      const updateData = {
        lastLogin: new Date(),
        role: user.isMember ? "member" : "user"
      };
      await usersCollection.updateOne(
        { _id: firebaseUid },
        { $set: updateData }
      );

      // Refresh user
      user = await usersCollection.findOne({ _id: firebaseUid });
    }

    res.send({ success: true, user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(401).send({ message: "Authentication failed", error: error.message });
  }
});

    // Get User Data
    app.get("/users/:uid", verifyToken, async (req, res) => {
      const { uid } = req.params;
      
      try {
        const user = await usersCollection.findOne({ _id: uid });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        
        // Verify the requesting user has access
        if (req.user.uid !== uid && req.user.role !== 'admin') {
          return res.status(403).send({ message: "Unauthorized access" });
        }

        res.send(user);
      } catch (error) {
        res.status(500).send({ message: "Error fetching user", error: error.message });
      }
    });

    // Update User Profile
    app.patch("/users/:uid", verifyToken, async (req, res) => {
      const { uid } = req.params;
      const updates = req.body;
      
      try {
        // Verify user can only update their own profile unless admin
        if (req.user.uid !== uid && req.user.role !== 'admin') {
          return res.status(403).send({ message: "Unauthorized" });
        }

        const result = await usersCollection.updateOne(
          { _id: uid },
          { $set: updates }
        );
        
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "User not found" });
        }
        
        res.send({ success: true, message: "Profile updated" });
      } catch (error) {
        res.status(500).send({ message: "Error updating profile", error: error.message });
      }
    });
    // ✅ Get recent posts for a user
app.get("/posts/user/:uid", async (req, res) => {
  const { uid } = req.params;
  const limit = parseInt(req.query.limit) || 0;

  try {
    const posts = await postsCollection
      .find({ authorId: uid }) // assumes your posts store authorId
      .sort({ createdAt: -1 }) // newest first
      .limit(limit)
      .toArray();

    res.send(posts);
  } catch (error) {
    console.error("Error fetching user posts:", error);
    res.status(500).send({ message: "Failed to fetch posts" });
  }
});
// admin ------

app.get("/admin/profile/:email", async (req, res) => {
      const email = req.params.email;
      const admin = await usersCollection.findOne({ email, role: "admin" });
      res.send(admin);
    });

    // 2️⃣ Get total site stats (posts, comments, users)
    app.get("/admin/stats", async (req, res) => {
      const [posts, comments, users] = await Promise.all([
        postsCollection.countDocuments(),
        commentsCollection.countDocuments(),
        usersCollection.countDocuments(),
      ]);
      res.send({ posts, comments, users });
    });

    // 3️⃣ Add a tag
    app.post("/admin/tags", async (req, res) => {
      const tag = req.body;
      const result = await tagsCollection.insertOne(tag);
      res.send(result);
    });

    // 4️⃣ Get all tags
    app.get("/admin/tags", async (req, res) => {
      const tags = await tagsCollection.find().toArray();
      res.send(tags);
    });

    // GET: All users with optional search by name
app.get("/admin/users", verifyToken, async (req, res) => {
  const search = req.query.search || "";
  const regex = new RegExp(search, "i");

  try {
    const users = await usersCollection
      .find({ name: { $regex: regex } })
      .project({ password: 0 }) // optional: exclude sensitive fields
      .toArray();
    res.send(users);
  } catch (error) {
    res.status(500).send({ message: "Error fetching users", error: error.message });
  }
});


    // Logout route
    app.post("/logout", (req, res) => {
      res.clearCookie("token").send({ success: true, message: "Logged out" });
    });

    // Stripe Checkout Session
   
app.post("/create-checkout-session", verifyToken, async (req, res) => {
  const { email, userId } = req.body;

  console.log("✅ Requested userId (Firebase UID):", userId); // Debug

  try {
    // Find user by Firebase UID (used as _id in MongoDB)
    const user = await usersCollection.findOne({ _id: userId });

    // Abort if user not found or already a member
    if (!user || user.isMember) {
      return res.status(400).send({ message: "You are already a member or invalid user." });
    }

    // Create Stripe Checkout Session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: email,
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "Gold Membership",
            },
            unit_amount: 100 * 100, // $1.00 or ৳100
          },
          quantity: 1,
        },
      ],
      success_url: `http://localhost:5173/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `http://localhost:5173/membership`,
      metadata: {
        userId: userId, // ✅ Save Firebase UID for later use
      },
    });

    console.log("✅ Stripe session created. ID:", session.id);
    res.send({ id: session.id });
  } catch (err) {
    console.error("❌ Stripe session creation failed:", err);
    res.status(500).send({ error: err.message || "Failed to create checkout session" });
  }
});


 // Verify Payment & Update User
app.post("/verify-session", verifyToken, async (req, res) => {
  const { sessionId } = req.body;

  // Log the sessionId and token to verify they are correct
  console.log("Received sessionId:", sessionId);
  console.log("Decoded user:", req.user);

  try {
    // Retrieve session from Stripe
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    // Check if payment was successful
    if (session.payment_status !== 'paid') {
      return res.status(402).json({ error: "Payment not completed" });
    }

    // Get user ID from session metadata (set during checkout)
    const userId = session.metadata?.userId;
    if (!userId) {
      return res.status(400).json({ error: "User ID not found in session" });
    }

    // Update user membership status
    const result = await usersCollection.updateOne(
      { _id: userId },
      { $set: { isMember: true, role: "member" } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "User not found or already a member" });
    }

    // Get updated user data to return
    const updatedUser = await usersCollection.findOne({ _id: userId });

    res.send({ 
      success: true,
      user: updatedUser
    });
  } catch (error) {
    console.error("Session verification error:", error);
    res.status(500).json({ error: "Failed to verify session", details: error.message });
  }
});


    // users
    app.get("/users", async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send({ message: "Email required" });

  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(404).send({ message: "User not found" });

  res.send(user);
});

// PATCH: Make a user admin
app.patch("/admin/make-admin/:uid", verifyToken, async (req, res) => {
  const { uid } = req.params;

  try {
    const result = await usersCollection.updateOne(
      { _id: uid },
      { $set: { role: "admin" } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send({ message: "User not found or already admin" });
    }

    res.send({ success: true, message: "User promoted to admin" });
  } catch (error) {
    res.status(500).send({ message: "Failed to promote user", error: error.message });
  }
});



    //  Search posts by tag
    app.get("/search", async (req, res) => {
      const query = req.query.q?.toLowerCase();
      if (!query) {
        return res.status(400).send({ message: "Search query required" });
      }
      try {
        const results = await postsCollection
          .find({ tags: { $in: [query] } })
          .toArray();
        res.send(results);
      } catch (error) {
        res.status(500).send({ message: "Error fetching results", error });
      }
    });

    // 🔥 Get popular posts sorted by vote difference (upVote - downVote)
    app.get("/popular-posts", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = 5;
      const skip = (page - 1) * limit;

      try {
        const totalPosts = await postsCollection.estimatedDocumentCount();
        const results = await postsCollection
          .aggregate([
            {
              $addFields: {
                voteDifference: {
                  $subtract: [
                    { $ifNull: ["$upVote", 0] },
                    { $ifNull: ["$downVote", 0] },
                  ],
                },
              },
            },
            { $sort: { voteDifference: -1 } },
            { $skip: skip },
            { $limit: limit },
          ])
          .toArray();

        res.send({
          totalPages: Math.ceil(totalPosts / limit),
          currentPage: page,
          posts: results,
        });
      } catch (error) {
        res.status(500).send({ message: "Failed to sort by popularity", error });
      }
    });

    // 📄 Get paginated posts (latest first)
    app.get("/posts", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = 5;
      const skip = (page - 1) * limit;

      try {
        const totalPosts = await postsCollection.estimatedDocumentCount();
        const posts = await postsCollection
          .find({})
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.send({
          totalPages: Math.ceil(totalPosts / limit),
          currentPage: page,
          posts,
        });
      } catch (error) {
        res.status(500).send({ message: "Failed to paginate", error });
      }
    });

      // ✅ Get Single Post + Comments
    app.get("/posts/:id", async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

      try {
        const post = await postsCollection.findOne({ _id: new ObjectId(id) });
        if (!post) return res.status(404).send({ message: "Post not found" });

        const comments = await commentsCollection
          .find({ postId: new ObjectId(id) })
          .sort({ createdAt: -1 })
          .toArray();

        post.comments = comments;
        res.send(post);
      } catch (error) {
        res.status(500).send({ message: "Error retrieving post", error: error.message });
      }
    });

    // ✅ Add Comment to a Post
   app.post("/posts/:id/comments", async (req, res) => {
  const { id } = req.params;
  const { commentText, userName, userEmail } = req.body;

  if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

  try {
    const post = await postsCollection.findOne({ _id: new ObjectId(id) });
    if (!post) return res.status(404).send({ message: "Post not found" });

    const comment = {
      postId: new ObjectId(id),
      commentText,
      postTitle: post.title,
      commentedBy: {
        name: userName,
        email: userEmail,
      },
      createdAt: new Date(),
    };

    const result = await commentsCollection.insertOne(comment);
    res.send({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).send({ message: "Error adding comment", error: error.message });
  }
});

// ✅ Upvote or Downvote a Post
app.patch("/posts/:id/:type", async (req, res) => {
  const { id, type } = req.params;
  if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

  if (!["upvote", "downvote"].includes(type)) {
    return res.status(400).send({ message: "Invalid vote type" });
  }

  // Map vote type to correct field name
  const voteField = type === "upvote" ? "upVote" : "downVote";

  try {
    const result = await postsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $inc: { [voteField]: 1 } }
    );
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: "Voting failed", error: error.message });
  }
});

// ✅ PATCH: Update Post (Author Only)
app.patch("/posts/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, description, tags, postImage } = req.body;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid post ID" });
  }

  try {
    const post = await postsCollection.findOne({ _id: new ObjectId(id) });

    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    if (post.authorId !== req.user.uid) {
      return res.status(403).json({ message: "Unauthorized to edit this post" });
    }

    await postsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          title,
          description,
          tags,
          postImage,
        },
      }
    );

    res.send({ success: true, message: "Post updated successfully" });
  } catch (error) {
    console.error("Error updating post:", error.message);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});


    // 🔹 Create a Post (for testing)
    app.post("/posts", verifyToken, async (req, res) => {
      const post = {
        ...req.body,
        
        createdAt: new Date(),
      };
      try {
        const result = await postsCollection.insertOne(post);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: "Error creating post", error: error.message });
      }
    });
    
// ✅ Delete a post with authorization check
app.delete("/posts/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.uid;  // From verified token

  console.log('UserID:', userId, 'PostID:', id);

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: "Invalid post ID" });
  }

  try {
    // Check if the post belongs to the current user
    const post = await postsCollection.findOne({ 
      _id: new ObjectId(id),
      authorId: userId  // Ensure user is the author of the post
    });

    if (!post) {
      return res.status(403).json({ 
        success: false, 
        message: "You are not authorized to delete this post" 
      });
    }

    // Proceed with deleting the post and its associated comments
    await commentsCollection.deleteMany({ postId: new ObjectId(id) });
    
    const result = await postsCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(500).json({ 
        success: false, 
        message: "Failed to delete post" 
      });
    }
    
    res.json({ 
      success: true,
      message: "Post and associated comments deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting post:", error.message);
    res.status(500).json({ 
      success: false,
      message: "Server error while deleting post",
      error: error.message 
    });
  }
});


    //  GET: All comments (for testing/debugging)
    app.get("/comments", async (req, res) => {
      try {
        const comments = await commentsCollection.find().toArray();
        res.json(comments);
      } catch (err) {
        res.status(500).json({ error: "Failed to fetch comments" });
      }
    });

    // ✅ 2. GET comments by Post ID
    app.get("/comments/:postId", async (req, res) => {
      const postId = req.params.postId;

      if (!ObjectId.isValid(postId)) {
        return res.status(400).json({ success: false, message: "Invalid Post ID format" });
      }

      try {
        const comments = await commentsCollection
          .find({ postId: new ObjectId(postId) })
          .sort({ createdAt: -1 })
          .toArray();

        res.json({
          success: true,
          postId,
          comments,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to fetch comments",
          error: error.message,
        });
      }
    });

    // ✅ 3. GET comment count by Post ID
    app.get("/comment-count/:postId", async (req, res) => {
      const postId = req.params.postId;

      if (!ObjectId.isValid(postId)) {
        return res.status(400).json({ success: false, message: "Invalid Post ID format" });
      }

      try {
        const count = await commentsCollection.countDocuments({
          postId: new ObjectId(postId),
        });

        res.json({
          success: true,
          postId,
          commentCount: count,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Error counting comments",
          error: error.message,
        });
      }
    });

    // ✅ 4. POST new comment
    app.post("/comments", async (req, res) => {
      const { postId, author, content } = req.body;

      if (!postId || !ObjectId.isValid(postId)) {
        return res.status(400).json({ success: false, message: "Invalid or missing postId" });
      }

      const comment = {
        postId: new ObjectId(postId),
        author,
        content,
        createdAt: new Date(),
      };

      try {
        const result = await commentsCollection.insertOne(comment);
        res.json({
          success: true,
          message: "Comment added successfully",
          commentId: result.insertedId,
        });
      } catch (err) {
        res.status(500).json({ success: false, message: "Failed to add comment", error: err.message });
      }
    });
   

    // report

app.patch('/comments/report/:commentId', verifyToken, async (req, res) => {
  const { commentId } = req.params;
  const { feedback } = req.body;
  const reporterId = req.user.uid; // Firebase UID (string)

  if (!ObjectId.isValid(commentId)) {
    return res.status(400).send({ message: "Invalid Comment ID" });
  }

  try {
    // Get reporter's details from users collection using the Firebase UID directly
    const reporter = await usersCollection.findOne({ _id: reporterId }); // No ObjectId conversion
    
    const result = await commentsCollection.updateOne(
      { _id: new ObjectId(commentId) },
      { 
        $set: { 
          isReported: true, 
          feedback,
          reportedBy: {
            name: reporter?.name || 'Anonymous',
            email: reporter?.email || 'unknown@example.com',
            userId: reporterId
          },
          reportedAt: new Date()
        } 
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send({ message: "Comment not found or already reported" });
    }

    res.send({ message: "Comment reported successfully", result });
  } catch (error) {
    console.error("Reporting error:", error);
    res.status(500).send({ 
      message: "Error reporting comment", 
      error: error.message 
    });
  }
});
// Announcementes route
app.post("/announcements", verifyToken, async (req, res) => {
  const { authorImage, authorName, title, description } = req.body;

  if (!authorName || !title || !description) {
    return res.status(400).send({ message: "Missing required fields" });
  }

  const announcement = {
    authorImage,
    authorName,
    title,
    description,
    createdAt: new Date()
  };

  try {
    const result = await announcementsCollection.insertOne(announcement);
    res.send({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).send({ message: "Failed to create announcement", error: error.message });
  }
});


app.get("/announcements", async (req, res) => {
  try {
    const announcements = await announcementsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.send(announcements);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch announcements", error: error.message });
  }
});

app.get("/announcements/count", async (req, res) => {
  try {
    const count = await announcementsCollection.countDocuments();
    res.send({ count });
  } catch (error) {
    res.status(500).send({ message: "Failed to count announcements", error: error.message });
  }
});

// get repoted comments
app.get("/admin/reported-comments", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const reportedComments = await commentsCollection  // Ensure correct collection name
      .find({ isReported: true })
      .sort({ createdAt: -1 })
      .toArray();
    
    res.send(reportedComments);
  } catch (error) {
    console.error("Error fetching reported comments:", error);
    res.status(500).send({ 
      error: "Failed to fetch reported comments",
      details: error.message 
    });
  }
});



app.patch("/admin/comments/dismiss/:id", verifyToken, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await commentsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { isReported: false } }
    );
    res.send({ message: "Report dismissed", modifiedCount: result.modifiedCount });
  } catch (err) {
    res.status(500).send({ error: "Failed to dismiss comment report" });
  }
});

app.delete("/admin/comments/:id", verifyToken, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await commentsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ message: "Comment deleted", deletedCount: result.deletedCount });
  } catch (err) {
    res.status(500).send({ error: "Failed to delete comment" });
  }
});

// DELETE announcement by ID (admin only)
app.delete("/admin/announcements/:id", verifyToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

  try {
    const result = await announcementsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to delete announcement", error: error.message });
  }
});

// PATCH: Update announcement
app.patch("/admin/announcements/:id", verifyToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });

  try {
    const result = await announcementsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res.status(500).send({ message: "Failed to update announcement", error: error.message });
  }
});


    // await client.db("admin").command({ ping: 1 });
    console.log("✅ Connected to MongoDB");
  } finally {
    // 🔁 Don't close the client during development
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("🌍 Climate forum is running...");
});

app.listen(port, () => {
  console.log(`🚀 Server is running on port ${port}`);
}); 