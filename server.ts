import express from "express";
import cors, { type CorsOptions } from "cors";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import helmet from "helmet"
import rateLimit from "express-rate-limit"

dotenv.config();

const env = {
  PORT: Number(process.env.PORT ?? 5000),

  MONGODB_URI:
    process.env.MONGODB_URI ?? "mongodb://127.0.0.1:27017",

  MONGODB_DB_NAME:
    process.env.MONGODB_DB_NAME ?? "gearhub",

  NODE_ENV: process.env.NODE_ENV ?? "development",

  CLIENT_URL: (process.env.CLIENT_URL ?? "http://localhost:3000").replace(/\/$/, ""),

  CLIENT_URLS: (process.env.CLIENT_URLS ?? "http://localhost:3000")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean),
};

const app = express();

//Middleware
const allowedOrigins = new Set([
  env.CLIENT_URL,
  ...env.CLIENT_URLS,
]);

const corsOptions: CorsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS blocked origin: ${origin}`));
  },

  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],

  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-Bootstrap-Secret",
  ],

  exposedHeaders: ["set-auth-jwt"],
  maxAge: 86400,
};

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);

app.use(cors(corsOptions));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api", apiLimiter);


const mongoClient = new MongoClient(env.MONGODB_URI, {
  serverSelectionTimeoutMS: 15000
})


app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "GearHub API is running!",
  });
});



app.listen(env.PORT, () => {
  console.log(`Server: http://localhost:${env.PORT}`);
});
