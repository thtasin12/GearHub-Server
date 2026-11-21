import express, {
  type NextFunction,
  type Request,
  type Response,
  type RequestHandler,
} from "express"
import cors, { type CorsOptions } from "cors";
import dotenv from "dotenv";
import {
  MongoClient,
  ObjectId,
  type Db,
  type Collection,
  type Document,
} from "mongodb";
import helmet from "helmet"
import rateLimit from "express-rate-limit"

let db!: Db;


type Role = "customer" | "owner" | "admin";

type AuthUser = {
  id: string;
  email: string;
  name: string;
  role: Role;
  image?: string;
}

type AuthRequest = Request & {
  authUser?: AuthUser;
}

type AnyDoc = Record<string, any>

type RentalType = "daily" | "weekly" | "monthly"

type EquipmentStatus = "pending" | "approved" | "rejected"

type BookingStatus =
  | "pending_payment"
  | "confirmed"
  | "in_progress"
  | "completed"
  | "cancelled"
  | "expired"
  | "payment_failed"


class AppError extends Error {
  statusCode: number;
  code?: string;

  constructor(message: string, statusCode = 400, code?: string) {
    super(message);
    this.statusCode = statusCode;

    if (code !== undefined) {
      this.code = code;
    }
  }
}


const asObjectId = (value: string, label = "id"): ObjectId => {
  if (!ObjectId.isValid(value)) {
    fail(`Invalid ${label}.`, 400, "INVALID_ID");
  }

  return new ObjectId(value);
};

const escapeRegex = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const cleanText = (value: unknown, max = 2000) =>
  String(value ?? "").trim().slice(0, max);

const now = () => new Date();

const addMinutes = (date: Date, minutes: number) =>
  new Date(date.getTime() + minutes * 60_000);

const isRole = (value: unknown): value is Role =>
  value === "customer" || value === "owner" || value === "admin";

const isValidDate = (value: unknown): value is string =>
  typeof value === "string" && !Number.isNaN(Date.parse(value));

const toDate = (value: string, field: string) => {
  if (!isValidDate(value)) {
    fail(`${field} must be a valid ISO date.`, 400, "INVALID_DATE");
  }

  return new Date(value);
};

const getCollection = <T extends Document = AnyDoc>(
  name: string
): Collection<T> => db.collection<T>(name);

const userCollection = () => getCollection("user")
const equipmentCollection = () => getCollection("equipment")
const bookingsCollection = () => getCollection("bookings")
const paymentsCollection = () => getCollection("payments")
const favoritesCollection = () => getCollection("favorites")
const reviewsCollection = () => getCollection("reviews")
const notificationsCollection = () => getCollection("notifications")
const conversationsCollection = () => getCollection("conversations")
const messagesCollection = () => getCollection("messages")
const handoversCollection = () => getCollection("handovers")
const extensionsCollection = () => getCollection("extensions")

const asyncHandler = (
  fn: (
    req: Request,
    res: Response,
    next: NextFunction
  ) => Promise<unknown> | unknown
): RequestHandler =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

const send = (
  res: Response,
  data: unknown,
  message = "Success",
  status = 200
) =>
  res.status(status).json({
    success: true,
    message,
    data,
  })

const fail = (
  message: string,
  status = 400,
  code?: string
): never => {
  throw new AppError(message, status, code);
}

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
