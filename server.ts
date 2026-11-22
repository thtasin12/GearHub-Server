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


import { betterAuth } from "better-auth"
import { mongodbAdapter } from "@better-auth/mongo-adapter"
import { jwt } from "better-auth/plugins"
import { APIError, createAuthMiddleware } from "better-auth/api"
import { toNodeHandler } from "better-auth/node"
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
} from "jose"
import Stripe from "stripe";
dotenv.config();

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

const asyncHandler = (
  fn: (
    req: Request,
    res: Response,
    next: NextFunction
  ) => Promise<unknown> | unknown
): RequestHandler =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next)


async function initializeAuth() {
  const googleConfigured = Boolean(
    env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
  );

  auth = betterAuth({
    database: /^(mongodb\+srv:|mongodb:.*[?&]replicaSet=)/i.test(
      env.MONGODB_URI
    )
      ? mongodbAdapter(db, { client: mongoClient })
      : mongodbAdapter(db),

    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
    trustedOrigins: [...allowedOrigins],

    emailAndPassword: {
      enabled: true,
      minPasswordLength: 6,
      maxPasswordLength: 128,
    },

    ...(googleConfigured
      ? {
        socialProviders: {
          google: {
            clientId: env.GOOGLE_CLIENT_ID,
            clientSecret: env.GOOGLE_CLIENT_SECRET,
          },
        },
      }
      : {}),

    user: {
      additionalFields: {
        role: {
          type: "string",
          required: false,
          defaultValue: "customer",
          input: false,
        },
        phone: {
          type: "string",
          required: false,
          input: false,
        },
        address: {
          type: "string",
          required: false,
          input: false,
        },
        isBlocked: {
          type: "boolean",
          required: false,
          defaultValue: false,
          input: false,
        },
      },
    },

    databaseHooks: {
      user: {
        create: {
          before: async (user) => ({
            data: {
              ...user,
              role: "customer",
              isBlocked: false,
            },
          }),
        },
      },
    },

    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        if (ctx.path === "/sign-up/email") {
          const body = ctx.body as
            | { password?: unknown }
            | undefined

          const password =
            typeof body?.password === "string"
              ? body.password
              : ""

          if (
            password.length < 6 ||
            !/[A-Z]/.test(password) ||
            !/[a-z]/.test(password)
          ) {
            throw new APIError("BAD_REQUEST", {
              message:
                "Password must contain an uppercase letter, a lowercase letter, and at least 6 characters.",
            })
          }
        }
      }),
    },

    plugins: [
      jwt({
        jwt: {
          expirationTime: "15m",
          definePayload: ({ user }) => {
            const customUser = user as typeof user & {
              role?: string;
            };

            return {
              email: user.email,
              name: user.name,
              role: customUser.role ?? "customer",
            };
          },
        },
        jwks: {
          rotationInterval: 60 * 60 * 24 * 30,
          gracePeriod: 60 * 60 * 24 * 30,
        },
      }),
    ],

    advanced: {
      defaultCookieAttributes: {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite:
          env.NODE_ENV === "production" ? "none" : "lax",
      },
    },

    rateLimit: {
      enabled: true,
      window: 60,
      max: 100,
    },


  }) as unknown as ReturnType<typeof betterAuth>;

  JWKS = createRemoteJWKSet(
    new URL(`${env.BETTER_AUTH_URL}/api/auth/jwks`)
  );

  betterAuthHandler = toNodeHandler(auth) as unknown as (
    req: Request,
    res: Response
  ) => void
}

const verifyToken: RequestHandler = asyncHandler(async (req, _res, next) => {
  const header = req.headers.authorization;

  if (
    typeof header !== "string" ||
    !header.startsWith("Bearer ")
  ) {
    fail("Authentication token is required.", 401, "UNAUTHORIZED");
  }

  const token = (header as string).slice(7).trim();

  if (!token) {
    fail("Authentication token is required.", 401, "UNAUTHORIZED");
  }

  let payload: JWTPayload | undefined;

  try {
    ({ payload } = await jwtVerify(token, JWKS, {
      issuer: env.BETTER_AUTH_URL,
      audience: env.BETTER_AUTH_URL,
    }));
  } catch {
    fail(
      "Invalid or expired access token. Please sign in again.",
      401,
      "INVALID_TOKEN"
    );
  }

  const resolvedPayload = payload!;

  const email =
    typeof resolvedPayload.email === "string"
      ? resolvedPayload.email.toLowerCase()
      : "";

  const subject =
    typeof resolvedPayload.sub === "string"
      ? resolvedPayload.sub
      : "";

  if (!email || !subject) {
    fail("Invalid access token payload.", 401, "INVALID_TOKEN");
  }


  const dbUser = await userCollection().findOne({ email });

  if (!dbUser || dbUser.isBlocked === true) {
    fail("Account is unavailable.", 401, "ACCOUNT_UNAVAILABLE");
  }

  const resolvedUser = dbUser!;

  const role: Role = isRole(resolvedUser.role)
    ? resolvedUser.role
    : "customer";

  (req as AuthRequest).authUser = {
    id: subject,
    email,
    name: String(
      resolvedUser.name ??
      resolvedPayload.name ??
      "GearHub User"
    ),
    role,
    ...(typeof resolvedUser.image === "string"
      ? { image: resolvedUser.image }
      : {}),
  };

  next();
});

const requireRole = (...roles: Role[]): RequestHandler =>
  (req, _res, next) => {
    const user = (req as AuthRequest).authUser;

    if (!user) {
      return next(
        new AppError("Authentication required.", 401)
      );
    }

    if (!roles.includes(user.role)) {
      return next(
        new AppError(
          "You do not have permission to perform this action.",
          403,
          "FORBIDDEN"
        )
      );
    }

    next();
  };

const verifyRenter = requireRole("customer");
const verifyOwner = requireRole("owner");
const verifyAdmin = requireRole("admin");

const currentUser = (req: Request): AuthUser => {
  const user = (req as AuthRequest).authUser;

  if (!user) {
    fail("Authentication required.", 401);
  }

  return user!;
}

function calculateRental(
  price: number,
  rentalType: RentalType,
  startAt: Date,
  endAt: Date,
  quantity: number
) {
  const durationMs = endAt.getTime() - startAt.getTime();

  if (durationMs <= 0) {
    fail("Rental end date must be after the start date.", 400, "INVALID_RENTAL_DATES");
  }

  const days = Math.max(1, Math.ceil(durationMs / 86_400_000));

  const periods =
    rentalType === "daily"
      ? days
      : rentalType === "weekly"
        ? Math.ceil(days / 7)
        : Math.ceil(days / 30)

  const unitPrice = Number(price);
  const total = Number((unitPrice * periods * quantity).toFixed(2));

  if (!Number.isFinite(total) || total <= 0) {
    fail("Could not calculate rental amount.", 400)
  }

  return { days, periods, rentalType, unitPrice, quantity, total };
}

function toStripeMinorUnits(amount: number, currency: string) {
  const zeroDecimal = new Set([
    "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw",
    "mga", "pyg", "rwf", "ugx", "vnd", "vuv", "xaf",
    "xof", "xpf",
  ])

  return Math.round(
    amount * (zeroDecimal.has(currency.toLowerCase()) ? 1 : 100)
  )
}

function requireStripe(): Stripe {
  if (!stripe) {
    fail(
      "Stripe is not configured. Add STRIPE_SECRET_KEY to the server environment.",
      503,
      "STRIPE_NOT_CONFIGURED"
    )
  }

  return stripe as Stripe;
}

async function notify(
  userId: string,
  type: string,
  title: string,
  message: string,
  link = ""
) {
  await notificationsCollection().insertOne({
    userId,
    type,
    title,
    message,
    link,
    read: false,
    createdAt: now(),
  })
}

async function equipmentById(id: string): Promise<AnyDoc> {
  const item = await equipmentCollection().findOne({
    _id: asObjectId(id, "equipment id"),
  })

  if (!item) {
    fail("Equipment not found.", 404, "EQUIPMENT_NOT_FOUND");
  }

  return item!
}

async function bookingById(id: string): Promise<AnyDoc> {
  const booking = await bookingsCollection().findOne({
    _id: asObjectId(id, "booking id"),
  })

  if (!booking) {
    fail("Booking not found.", 404, "BOOKING_NOT_FOUND");
  }

  return booking!
}

async function assertBookingParticipant(
  booking: AnyDoc,
  user: AuthUser
) {
  if (user.role === "admin") return;

  if (
    booking.customerId !== user.id &&
    booking.ownerId !== user.id
  ) {
    fail("You cannot access this booking.", 403)
  }
}

async function createStripeCheckout(params: {
  amount: number;
  currency?: string;
  productName: string;
  description: string;
  customerEmail: string;
  metadata: Record<string, string>;
  successUrl?: string;
  cancelUrl?: string;
  idempotencyKey: string;
}) {
  const stripeClient = requireStripe();

  const currency = (
    params.currency ?? env.STRIPE_CURRENCY
  ).toLowerCase();

  const amountMinor = toStripeMinorUnits(
    params.amount,
    currency
  );

  if (amountMinor < 1) {
    fail("Payment amount is below Stripe's minimum.", 400);
  }

  return stripeClient.checkout.sessions.create(
    {
      mode: "payment",
      customer_email: params.customerEmail,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency,
            unit_amount: amountMinor,
            product_data: {
              name: params.productName,
              description: params.description.slice(0, 500),
            },
          },
        },
      ],
      metadata: params.metadata,
      success_url: params.successUrl ?? env.STRIPE_SUCCESS_URL,
      cancel_url: params.cancelUrl ?? env.STRIPE_CANCEL_URL,
      billing_address_collection: "auto",
    },
    { idempotencyKey: params.idempotencyKey }
  );
}

async function checkAvailability(
  equipmentId: ObjectId,
  startAt: Date,
  endAt: Date,
  requestedQuantity: number,
  capacity: number,
  excludeBookingId?: ObjectId
) {
  const overlapQuery: AnyDoc = {
    equipmentId,
    $and: [
      {
        $or: [
          {
            bookingStatus: {
              $in: ["confirmed", "in_progress"],
            },
          },
          {
            bookingStatus: "pending_payment",
            holdExpiresAt: { $gt: now() },
          },
        ],
      },
      { startAt: { $lt: endAt } },
      { endAt: { $gt: startAt } },
    ],
  }

  if (excludeBookingId) {
    overlapQuery._id = { $ne: excludeBookingId };
  }

  const result = await bookingsCollection()
    .aggregate([
      { $match: overlapQuery },
      {
        $group: {
          _id: null,
          reserved: { $sum: "$requiredQuantity" },
        },
      },
    ])
    .toArray()

  const reserved = Number(result[0]?.reserved ?? 0)
  const remaining = Math.max(0, capacity - reserved)

  if (requestedQuantity > remaining) {
    fail(
      `Only ${remaining} unit(s) are available for the selected rental period.`,
      409,
      "INSUFFICIENT_AVAILABILITY"
    )
  }

  return {
    reserved,
    remaining: remaining - requestedQuantity,
  }
}

async function getEquipmentAvailability(
  item: AnyDoc,
  startAt: Date,
  endAt: Date
) {
  const result = await bookingsCollection()
    .aggregate([
      {
        $match: {
          equipmentId: item._id,
          $and: [
            {
              $or: [
                {
                  bookingStatus: {
                    $in: ["confirmed", "in_progress"],
                  },
                },
                {
                  bookingStatus: "pending_payment",
                  holdExpiresAt: { $gt: now() },
                },
              ],
            },
            { startAt: { $lt: endAt } },
            { endAt: { $gt: startAt } },
          ],
        },
      },
      {
        $group: {
          _id: null,
          reserved: { $sum: "$requiredQuantity" },
        },
      },
    ])
    .toArray()

  const reserved = Number(result[0]?.reserved ?? 0);

  return {
    reserved,
    remaining: Math.max(
      0,
      Number(item.availableQuantity) - reserved
    ),
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

  BETTER_AUTH_SECRET: process.env.BETTER_AUTH_SECRET ?? "",
  BETTER_AUTH_URL: (
    process.env.BETTER_AUTH_URL ?? "http://localhost:5000"
  ).replace(/\/$/, ""),
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID ?? "",
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET ?? "",
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY ?? "",
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET ?? "",
  STRIPE_CURRENCY: (process.env.STRIPE_CURRENCY ?? "bdt").toLowerCase(),
  STRIPE_SUCCESS_URL:
    process.env.STRIPE_SUCCESS_URL ??
    "http://localhost:3000/payment/success?session_id={CHECKOUT_SESSION_ID}",
  STRIPE_CANCEL_URL:
    process.env.STRIPE_CANCEL_URL ??
    "http://localhost:3000/payment/cancel",
  PAYMENT_HOLD_MINUTES: Math.max(
    5,
    Number(process.env.PAYMENT_HOLD_MINUTES ?? 20)
  ),
};

if (env.BETTER_AUTH_SECRET.length < 32) {
  throw new Error("BETTER_AUTH_SECRET must be at least 32 characters. Set it in .env.");
}

const app = express();

const stripe: Stripe | null = env.STRIPE_SECRET_KEY.startsWith("sk_")
  ? new Stripe(env.STRIPE_SECRET_KEY)
  : null;

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
app.use(express.json())

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

app.use("/api", apiLimiter)

let auth: ReturnType<typeof betterAuth> = undefined as any;

let betterAuthHandler:
  | ((req: Request, res: Response) => void)
  | undefined;


let JWKS: ReturnType<typeof createRemoteJWKSet> = undefined as any


const mongoClient = new MongoClient(env.MONGODB_URI, {
  serverSelectionTimeoutMS: 15000
})

app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  asyncHandler(async (req, res) => {
    const stripeClient = requireStripe()

    if (!env.STRIPE_WEBHOOK_SECRET) {
      fail("STRIPE_WEBHOOK_SECRET is not configured.", 503);
    }

    const signature = req.headers["stripe-signature"];

    if (typeof signature !== "string") {
      fail("Missing Stripe signature.", 400)
    }

    let event: Stripe.Event | undefined

    try {
      event = stripeClient.webhooks.constructEvent(
        req.body as Buffer,
        signature as string,
        env.STRIPE_WEBHOOK_SECRET
      );
    } catch (error) {
      fail(
        `Invalid Stripe webhook signature: ${error instanceof Error
          ? error.message
          : "verification failed"
        }`,
        400,
        "INVALID_STRIPE_SIGNATURE"
      )
    }

    const resolvedEvent = event!

    const alreadyProcessed =
      await getCollection("processedStripeEvents").findOne({
        stripeEventId: resolvedEvent.id,
      })

    if (alreadyProcessed) {
      return send(res, { received: true, duplicate: true })
    }

    if (
      [
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
      ].includes(resolvedEvent.type)
    ) {
      const session =
        resolvedEvent.data.object as Stripe.Checkout.Session;

      const payment = await paymentsCollection().findOne({
        stripeSessionId: session.id,
      })

      if (payment) {
        const amountMatches =
          Number(session.amount_total) === Number(payment.amountMinor)

        const currencyMatches =
          String(session.currency).toLowerCase() ===
          String(payment.currency).toLowerCase()

        const metadataMatches =
          session.metadata?.paymentId === String(payment._id)

        if (!amountMatches || !currencyMatches || !metadataMatches) {
          await paymentsCollection().updateOne(
            { _id: payment._id },
            {
              $set: {
                status: "review_required",
                webhookWarning:
                  "Stripe amount/currency/metadata mismatch",
                updatedAt: now(),
              },
            }
          )
        } else if (session.payment_status === "paid") {
          if (payment.purpose === "booking") {
            const booking = await bookingsCollection().findOne({
              _id: payment.bookingId,
            })

            if (
              booking &&
              !["cancelled", "expired"].includes(booking.bookingStatus)
            ) {
              await paymentsCollection().updateOne(
                {
                  _id: payment._id,
                  status: { $ne: "paid" },
                },
                {
                  $set: {
                    status: "paid",
                    stripePaymentIntentId:
                      typeof session.payment_intent === "string"
                        ? session.payment_intent
                        : null,
                    paidAt: now(),
                    updatedAt: now(),
                  },
                }
              )

              await bookingsCollection().updateOne(
                {
                  _id: booking._id,
                  paymentStatus: { $ne: "paid" },
                },
                {
                  $set: {
                    paymentStatus: "paid",
                    bookingStatus: "confirmed",
                    paidAt: now(),
                    updatedAt: now(),
                  },
                }
              )

              await equipmentCollection().updateOne(
                { _id: booking.equipmentId },
                { $inc: { totalRentals: 1 } }
              )

              await notify(
                booking.customerId,
                "payment_success",
                "Payment successful",
                `Your ${booking.equipmentName} rental is confirmed.`,
                "/dashboard/customer/rentals"
              )

              await notify(
                booking.ownerId,
                "payment_success",
                "New paid booking",
                `${booking.equipmentName} has a confirmed rental.`,
                "/dashboard/owner/rentals"
              );
            } else {
              const intent =
                typeof session.payment_intent === "string"
                  ? session.payment_intent
                  : null;

              if (intent) {
                await stripeClient.refunds.create({
                  payment_intent: intent,
                  reason: "requested_by_customer",
                })
              }

              await paymentsCollection().updateOne(
                { _id: payment._id },
                {
                  $set: {
                    status: "refunded",
                    refundedAt: now(),
                    updatedAt: now(),
                  },
                }
              )
            }
          } else if (payment.purpose === "extension") {
            const extension = await extensionsCollection().findOne({
              _id: payment.extensionId,
              status: "approved",
            })

            if (extension) {
              await extensionsCollection().updateOne(
                { _id: extension._id },
                {
                  $set: {
                    status: "paid",
                    paidAt: now(),
                  },
                }
              );

              await bookingsCollection().updateOne(
                { _id: extension.bookingId },
                {
                  $set: {
                    endAt: extension.newEndAt,
                    updatedAt: now(),
                  },
                  $inc: {
                    totalAmount: Number(extension.amount),
                  },
                }
              );

              await paymentsCollection().updateOne(
                { _id: payment._id },
                {
                  $set: {
                    status: "paid",
                    stripePaymentIntentId:
                      typeof session.payment_intent === "string"
                        ? session.payment_intent
                        : null,
                    paidAt: now(),
                  },
                }
              );
            }
          }
        }
      }
    } else if (
      resolvedEvent.type === "checkout.session.expired" ||
      resolvedEvent.type === "checkout.session.async_payment_failed"
    ) {
      const session =
        resolvedEvent.data.object as Stripe.Checkout.Session;

      const payment = await paymentsCollection().findOne({
        stripeSessionId: session.id,
      })

      if (payment && payment.status !== "paid") {
        await paymentsCollection().updateOne(
          { _id: payment._id },
          {
            $set: {
              status: "failed",
              updatedAt: now(),
            },
          }
        )

        if (payment.purpose === "booking") {
          await bookingsCollection().updateOne(
            {
              _id: payment.bookingId,
              paymentStatus: { $ne: "paid" },
            },
            {
              $set: {
                paymentStatus: "failed",
                bookingStatus: "payment_failed",
                updatedAt: now(),
              },
            }
          );
        }
      }
    }

    await getCollection("processedStripeEvents").insertOne({
      stripeEventId: resolvedEvent.id,
      type: resolvedEvent.type,
      processedAt: now(),
    })

    send(res, { received: true })
  })
)

app.use(express.json({ limit: "2mb" }))
app.use(express.urlencoded({ extended: true, limit: "1mb" }))

app.get("/api/equipment/featured", asyncHandler(async (req, res) => {
  const limit = Math.min(
    12,
    Math.max(1, Number(req.query.limit ?? 6) || 6)
  );

  const items = await equipmentCollection()
    .find({ status: "approved" })
    .sort({ featured: -1, createdAt: -1 })
    .limit(limit)
    .toArray()

  send(res, items)
}))

app.get("/api/equipment/nearby", asyncHandler(async (req, res) => {
  const latitude = Number(req.query.lat);
  const longitude = Number(req.query.lng);

  const maxDistance = Math.min(
    100000,
    Math.max(100, Number(req.query.maxDistance ?? 25000))
  )

  if (
    !Number.isFinite(latitude) ||
    !Number.isFinite(longitude) ||
    Math.abs(latitude) > 90 ||
    Math.abs(longitude) > 180
  ) {
    fail("Valid lat and lng query parameters are required.")
  }

  const items = await equipmentCollection()
    .find({
      status: "approved",
      "location.geo": {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [longitude, latitude],
          },
          $maxDistance: maxDistance,
        },
      },
    })
    .limit(30)
    .toArray()

  send(res, items)
}))

app.get("/api/equipment/compare", asyncHandler(async (req, res) => {
  const ids = String(req.query.ids ?? "")
    .split(",")
    .filter(Boolean)
    .slice(0, 4)

  if (ids.length < 2) {
    fail("Provide at least 2 equipment ids and no more than 4.")
  }

  const objectIds = ids.map((id) =>
    asObjectId(id, "equipment id")
  )

  const items = await equipmentCollection()
    .find({
      _id: { $in: objectIds },
      status: "approved",
    })
    .toArray()

  send(res, items)
}))

app.get("/api/equipment", asyncHandler(async (req, res) => {
  const page = Math.max(
    1,
    Number(req.query.page ?? 1) || 1
  )

  const limit = Math.min(
    48,
    Math.max(1, Number(req.query.limit ?? 9) || 9)
  )

  const filter: AnyDoc = { status: "approved" }

  const search = cleanText(
    req.query.search ?? req.query.q,
    80
  )

  if (search) {
    const regex = new RegExp(escapeRegex(search), "i");

    filter.$or = [
      { name: regex },
      { description: regex },
      { "location.city": regex },
      { "location.address": regex },
      { brand: regex },
      { model: regex },
    ];
  }

  if (req.query.category) {
    filter.category = cleanText(req.query.category, 100)
  }

  if (req.query.rentalType) {
    if (
      !["daily", "weekly", "monthly"].includes(
        String(req.query.rentalType)
      )
    ) {
      fail("Invalid rentalType filter.")
    }

    filter.rentalType = String(req.query.rentalType)
  }

  if (
    req.query.minPrice !== undefined ||
    req.query.maxPrice !== undefined
  ) {
    const min =
      req.query.minPrice === undefined
        ? 0
        : Number(req.query.minPrice)

    const max =
      req.query.maxPrice === undefined
        ? Number.MAX_SAFE_INTEGER
        : Number(req.query.maxPrice)

    if (
      !Number.isFinite(min) ||
      !Number.isFinite(max) ||
      min < 0 ||
      max < min
    ) {
      fail("Invalid price range.");
    }

    filter.rentalPrice = {
      $gte: min,
      $lte: max,
    }
  }

  const sortKey = String(req.query.sort ?? "recent");

  const sortMap = {
    recent: { createdAt: -1 },
    price_asc: { rentalPrice: 1 },
    price_desc: { rentalPrice: -1 },
    rating: { averageRating: -1, createdAt: -1 },
    popular: { totalRentals: -1 },
  } as const

  if (!Object.prototype.hasOwnProperty.call(sortMap, sortKey)) {
    fail("Invalid sort option.")
  }

  const sortOption = sortMap[sortKey as keyof typeof sortMap]

  const [items, total] = await Promise.all([
    equipmentCollection()
      .find(filter)
      .sort(sortOption)
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray(),

    equipmentCollection().countDocuments(filter),
  ])

  let enhanced: AnyDoc[] = items

  const from =
    typeof req.query.from === "string"
      ? req.query.from
      : ""

  const to =
    typeof req.query.to === "string"
      ? req.query.to
      : ""

  if (from || to) {
    if (
      !from ||
      !to ||
      !isValidDate(from) ||
      !isValidDate(to) ||
      new Date(to) <= new Date(from)
    ) {
      fail(
        "Provide valid from and to dates for availability filtering."
      )
    }

    enhanced = await Promise.all(
      items.map(async (item) => ({
        ...item,
        ...(await getEquipmentAvailability(
          item,
          new Date(from),
          new Date(to)
        )),
      }))
    )

    if (req.query.availableOnly === "true") {
      enhanced = enhanced.filter(
        (item) => item.remaining > 0
      )
    }
  } else if (req.query.availableOnly === "true") {
    enhanced = items.filter(
      (item) => Number(item.availableQuantity) > 0
    )
  }

  send(res, {
    items: enhanced,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  })
}))


app.get(
  "/api/equipment/:id/availability",
  asyncHandler(async (req, res) => {
    const id = req.params.id;

    if (typeof id !== "string") {
      fail("Invalid equipment ID.", 400, "INVALID_ID")
    }

    const equipmentId = req.params.id;

    if (typeof equipmentId !== "string") {
      throw new AppError("Invalid equipment ID.", 400, "INVALID_ID")
    }

    const item = await equipmentById(equipmentId)
    if (item.status !== "approved") {
      fail("Equipment is not available.", 404)
    }

    const from = toDate(
      String(req.query.from ?? ""),
      "from"
    )

    const to = toDate(
      String(req.query.to ?? ""),
      "to"
    )

    if (to <= from) {
      fail("The end date must be after the start date.")
    }

    const reservations = await bookingsCollection()
      .find(
        {
          equipmentId: item._id,
          $and: [
            {
              $or: [
                {
                  bookingStatus: {
                    $in: ["confirmed", "in_progress"],
                  },
                },
                {
                  bookingStatus: "pending_payment",
                  holdExpiresAt: { $gt: now() },
                },
              ],
            },
            { startAt: { $lt: to } },
            { endAt: { $gt: from } },
          ],
        },
        {
          projection: {
            startAt: 1,
            endAt: 1,
            requiredQuantity: 1,
            bookingStatus: 1,
          },
        }
      )
      .sort({ startAt: 1 })
      .toArray()

    send(res, {
      capacity: item.availableQuantity,
      reservations,
    })
  })
)

app.get(
  "/api/equipment/:id",
  asyncHandler(async (req, res) => {
    const id = req.params.id

    if (typeof id !== "string") {
      fail("Invalid equipment ID.", 400, "INVALID_ID")
    }

    const equipmentId = req.params.id

    if (typeof equipmentId !== "string") {
      throw new AppError("Invalid equipment ID.", 400, "INVALID_ID")
    }

    const item = await equipmentById(equipmentId)

    if (item.status !== "approved") {
      const user = (req as AuthRequest).authUser

      if (
        !user ||
        (user.role !== "admin" && user.id !== item.ownerId)
      ) {
        fail("Equipment not found.", 404)
      }
    }

    const [owner, reviews] = await Promise.all([
      userCollection().findOne(
        { email: item.ownerEmail },
        {
          projection: {
            name: 1,
            image: 1,
            email: 1,
            createdAt: 1,
          },
        }
      ),

      reviewsCollection()
        .find({ equipmentId: item._id })
        .sort({ createdAt: -1 })
        .limit(10)
        .toArray(),
    ]);

    send(res, {
      ...item,
      owner: owner
        ? {
          name: owner.name,
          image: owner.image,
          email: owner.email,
          memberSince: owner.createdAt,
        }
        : null,
      reviews,
    })
  })
)


app.post("/api/equipment", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const rawBody: unknown = req.body

  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    fail("Invalid equipment data.")
  }

  const body = rawBody as AnyDoc

  const rawLocation: unknown = body.location

  if (!rawLocation || typeof rawLocation !== "object" || Array.isArray(rawLocation)) {
    fail("Equipment location is required.")
  }

  const locationInput = rawLocation as AnyDoc

  const description = typeof body.description === "string" ? body.description.trim() : ""

  if (description.length < 20 || description.length > 5000) {
    fail("Description must be between 20 and 5000 characters.")
  }

  const categories = [
    "Construction Equipment",
    "Photography Equipment",
    "Vehicles & Transportation",
    "Agriculture Equipment",
    "Electronics",
    "Event Equipment",
    "Other",
  ]

  if (!categories.includes(body.category)) {
    fail("Invalid equipment category.")
  }


  const city = typeof locationInput.city === "string" ? locationInput.city.trim() : ""
  const address = typeof locationInput.address === "string" ? locationInput.address.trim() : ""

  const country = locationInput.country === undefined
    ? "Bangladesh"
    : typeof locationInput.country === "string"
      ? locationInput.country.trim()
      : ""

  if (city.length < 2 || city.length > 100) fail("Invalid city.")
  if (address.length < 3 || address.length > 250) fail("Invalid address.")
  if (country.length < 2 || country.length > 100) fail("Invalid country.")


  const latitude = locationInput.latitude
  const longitude = locationInput.longitude

  if (latitude !== undefined && (typeof latitude !== "number" || !Number.isFinite(latitude))) {
    fail("Invalid latitude.")
  }

  if (longitude !== undefined && (typeof longitude !== "number" || !Number.isFinite(longitude))) {
    fail("Invalid longitude.")
  }

  const rentalPrice = body.rentalPrice

  if (
    typeof rentalPrice !== "number" ||
    !Number.isFinite(rentalPrice) ||
    rentalPrice <= 0 ||
    rentalPrice > 100000000
  ) {
    fail("Invalid rental price.")
  }

  if (!["daily", "weekly", "monthly"].includes(body.rentalType)) {
    fail("Invalid rental type.")
  }


  const availableQuantity = body.availableQuantity
  if (
    !Number.isInteger(availableQuantity) ||
    availableQuantity < 1 ||
    availableQuantity > 10000
  ) {
    fail("Available quantity must be between 1 and 10000.")
  }

  const condition = body.condition

  if (!["New", "Like New", "Good", "Fair"].includes(condition)) {
    fail("Invalid equipment condition.")
  }

  if (body.brand !== undefined && typeof body.brand !== "string") {
    fail("Invalid brand.")
  }

  if (body.model !== undefined && typeof body.model !== "string") {
    fail("Invalid model.")
  }

  const brand = typeof body.brand === "string" ? body.brand.trim() : ""
  const model = typeof body.model === "string" ? body.model.trim() : ""

  if (brand.length > 100 || model.length > 100) {
    fail("Brand and model must not exceed 100 characters.")
  }

  const isValidUrl = (value: unknown): value is string => {
    if (typeof value !== "string") return false

    try {
      new URL(value)
      return true
    } catch {
      return false
    }
  };

  if (!isValidUrl(body.image) || body.image.length > 2000) {
    fail("A valid equipment image URL is required.")
  }

  if (body.gallery !== undefined && !Array.isArray(body.gallery)) {
    fail("Gallery must be an array.")
  }

  const gallery = Array.isArray(body.gallery) ? body.gallery : []

  if (gallery.length > 10 || !gallery.every(isValidUrl)) {
    fail("Gallery can contain up to 10 valid image URLs.")
  }

  if (body.rentalTerms !== undefined && typeof body.rentalTerms !== "string") {
    fail("Invalid rental terms.")
  }

  const rentalTerms = typeof body.rentalTerms === "string"
    ? body.rentalTerms.trim()
    : "Please handle the equipment carefully and return it on time."

  if (rentalTerms.length > 4000) {
    fail("Rental terms must not exceed 4000 characters.")
  }

  const user = currentUser(req);


  const geo = latitude !== undefined && longitude !== undefined
    ? {
      type: "Point",
      coordinates: [longitude, latitude],
    }
    : undefined

  const record = {
    name,
    description,
    category: body.category,

    location: {
      city,
      address,
      country,
      ...(geo ? { geo } : {}),
    },

    rentalPrice,
    rentalType: body.rentalType,
    availableQuantity,
    condition,
    brand,
    model,
    image: body.image,
    gallery,
    rentalTerms,

    ownerId: user.id,
    ownerEmail: user.email,
    ownerName: user.name,

    status: "pending" as EquipmentStatus,
    averageRating: 0,
    reviewCount: 0,
    totalRentals: 0,

    createdAt: now(),
    updatedAt: now(),
  };

  const result = await equipmentCollection().insertOne(record);

  send(
    res,
    { ...record, _id: result.insertedId },
    "Equipment submitted for admin approval.",
    201
  )
}))


app.get("/api/owner/equipment", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const page = Math.max(1, Number(req.query.page ?? 1) || 1)
  const limit = Math.min(100, Math.max(1, Number(req.query.limit ?? 20) || 20))

  const [items, total] = await Promise.all([
    equipmentCollection()
      .find({ ownerId: user.id })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray(),

    equipmentCollection().countDocuments({ ownerId: user.id }),
  ])

  send(res, {
    items,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  })
}))


app.get("/api/owner/equipment/:id", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const user = currentUser(req);
  const equipmentId =
    typeof req.params.id === "string" ? req.params.id : "";

  const item = await equipmentCollection().findOne({
    _id: asObjectId(equipmentId, "equipment id"),
    ownerId: user.id,
  });

  if (!item) {
    fail("Equipment not found or not owned by you.", 404);
  }

  send(res, item);
}))



app.patch("/api/equipment/:id", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const user = currentUser(req);

  const equipmentId =
    typeof req.params.id === "string" ? req.params.id : ""

  const id = asObjectId(equipmentId, "equipment id")

  const existing = await equipmentCollection().findOne({
    _id: id,
    ownerId: user.id,
  })

  if (!existing) {
    fail("Equipment not found or not owned by you.", 404)
  }

  const rawBody: unknown = req.body

  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    fail("Invalid equipment data.")
  }

  const body = rawBody as AnyDoc

  const update: AnyDoc = {
    updatedAt: now(),
    status: "pending",
  }

  if (body.name !== undefined) {
    if (typeof body.name !== "string") {
      fail("Invalid equipment name.")
    }

    const name = body.name.trim()

    if (name.length < 3 || name.length > 120) {
      fail("Equipment name must be between 3 and 120 characters.")
    }

    update.name = name
  }

  if (body.description !== undefined) {
    if (typeof body.description !== "string") {
      fail("Invalid equipment description.")
    }

    const description = body.description.trim()

    if (description.length < 20 || description.length > 5000) {
      fail("Description must be between 20 and 5000 characters.")
    }

    update.description = description
  }

  if (body.category !== undefined) {
    const categories = [
      "Construction Equipment",
      "Photography Equipment",
      "Vehicles & Transportation",
      "Agriculture Equipment",
      "Electronics",
      "Event Equipment",
      "Other",
    ];

    if (!categories.includes(body.category)) {
      fail("Invalid equipment category.")
    }

    update.category = body.category
  }

  // Validate and update location
  if (body.location !== undefined) {
    const rawLocation: unknown = body.location
    if (
      !rawLocation ||
      typeof rawLocation !== "object" ||
      Array.isArray(rawLocation)
    ) {
      fail("Invalid equipment location.")
    }

    const location = rawLocation as AnyDoc

    const city =
      typeof location.city === "string" ? location.city.trim() : ""

    const address =
      typeof location.address === "string" ? location.address.trim() : ""

    const country =
      location.country === undefined
        ? "Bangladesh"
        : typeof location.country === "string"
          ? location.country.trim()
          : ""

    if (city.length < 2 || city.length > 100) {
      fail("Invalid city.")
    }

    if (address.length < 3 || address.length > 250) {
      fail("Invalid address.")
    }

    if (country.length < 2 || country.length > 100) {
      fail("Invalid country.")
    }

    const latitude = location.latitude
    const longitude = location.longitude

    if (
      latitude !== undefined &&
      (typeof latitude !== "number" || !Number.isFinite(latitude))
    ) {
      fail("Invalid latitude.")
    }

    if (
      longitude !== undefined &&
      (typeof longitude !== "number" || !Number.isFinite(longitude))
    ) {
      fail("Invalid longitude.")
    }

    const updatedLocation: AnyDoc = {
      city,
      address,
      country,
    };

    if (latitude !== undefined) updatedLocation.latitude = latitude
    if (longitude !== undefined) updatedLocation.longitude = longitude

    if (latitude !== undefined && longitude !== undefined) {
      updatedLocation.geo = {
        type: "Point",
        coordinates: [longitude, latitude],
      }
    }

    update.location = updatedLocation
  }

  if (body.rentalPrice !== undefined) {
    if (
      typeof body.rentalPrice !== "number" ||
      !Number.isFinite(body.rentalPrice) ||
      body.rentalPrice <= 0 ||
      body.rentalPrice > 100000000
    ) {
      fail("Invalid rental price.")
    }

    update.rentalPrice = body.rentalPrice
  }

  if (body.rentalType !== undefined) {
    if (!["daily", "weekly", "monthly"].includes(body.rentalType)) {
      fail("Invalid rental type.")
    }

    update.rentalType = body.rentalType
  }

  if (body.availableQuantity !== undefined) {
    if (
      !Number.isInteger(body.availableQuantity) ||
      body.availableQuantity < 1 ||
      body.availableQuantity > 10000
    ) {
      fail("Invalid available quantity.")
    }

    update.availableQuantity = body.availableQuantity
  }

  if (body.condition !== undefined) {
    if (!["New", "Like New", "Good", "Fair"].includes(body.condition)) {
      fail("Invalid equipment condition.")
    }

    update.condition = body.condition
  }

  if (body.brand !== undefined) {
    if (typeof body.brand !== "string") {
      fail("Invalid brand.")
    }

    const brand = body.brand.trim()

    if (brand.length > 100) {
      fail("Brand must not exceed 100 characters.")
    }

    update.brand = brand
  }

  if (body.model !== undefined) {
    if (typeof body.model !== "string") {
      fail("Invalid model.")
    }

    const model = body.model.trim()

    if (model.length > 100) {
      fail("Model must not exceed 100 characters.")
    }

    update.model = model
  }

  const isValidUrl = (value: unknown): value is string => {
    if (typeof value !== "string") return false

    try {
      new URL(value)
      return true
    } catch {
      return false
    }
  };

  if (body.image !== undefined) {
    if (!isValidUrl(body.image) || body.image.length > 2000) {
      fail("Invalid equipment image URL.")
    }

    update.image = body.image
  }

  if (body.gallery !== undefined) {
    if (!Array.isArray(body.gallery)) {
      fail("Gallery must be an array.")
    }

    if (body.gallery.length > 10 || !body.gallery.every(isValidUrl)) {
      fail("Gallery can contain up to 10 valid image URLs.")
    }

    update.gallery = body.gallery
  }

  if (body.rentalTerms !== undefined) {
    if (typeof body.rentalTerms !== "string") {
      fail("Invalid rental terms.");
    }

    const rentalTerms = body.rentalTerms.trim()

    if (rentalTerms.length > 4000) {
      fail("Rental terms must not exceed 4000 characters.")
    }

    update.rentalTerms = rentalTerms
  }

  await equipmentCollection().updateOne(
    { _id: id, ownerId: user.id },
    { $set: update }
  );

  const updatedItem = await equipmentCollection().findOne({
    _id: id,
    ownerId: user.id,
  });

  send(
    res,
    updatedItem,
    "Equipment updated and resubmitted for approval."
  )
}))


app.delete("/api/equipment/:id", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const user = currentUser(req);

  const equipmentId =
    typeof req.params.id === "string" ? req.params.id : ""

  const id = asObjectId(equipmentId, "equipment id")

  const activeBookings = await bookingsCollection().countDocuments({
    equipmentId: id,
    bookingStatus: {
      $in: ["confirmed", "in_progress", "pending_payment"],
    },
  })

  if (activeBookings) {
    fail("Equipment with active bookings cannot be deleted.", 409);
  }


  const result = await equipmentCollection().deleteOne({
    _id: id,
    ownerId: user.id,
  })

  if (!result.deletedCount) {
    fail("Equipment not found or not owned by you.", 404);
  }

  await favoritesCollection().deleteMany({
    equipmentId: id,
  })

  send(res, null, "Equipment deleted.");
}))


app.post("/api/bookings", verifyToken, verifyRenter, asyncHandler(async (req, res) => {
  const rawBody: unknown = req.body

  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    fail("Invalid booking information.")
  }

  const body = rawBody as AnyDoc

  const equipmentId = body.equipmentId

  if (typeof equipmentId !== "string" || equipmentId.length < 1) {
    fail("Equipment ID is required.")
  }

  const startAtValue = body.startAt

  const dateTimeWithOffset =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/

  if (
    typeof startAtValue !== "string" ||
    !dateTimeWithOffset.test(startAtValue) ||
    !isValidDate(startAtValue)
  ) {
    fail("Start date must be a valid ISO date with timezone.")
  }

  const endAtValue = body.endAt

  if (
    typeof endAtValue !== "string" ||
    !dateTimeWithOffset.test(endAtValue) ||
    !isValidDate(endAtValue)
  ) {
    fail("End date must be a valid ISO date with timezone.")
  }

  const requiredQuantity = body.requiredQuantity

  if (
    typeof requiredQuantity !== "number" ||
    !Number.isInteger(requiredQuantity) ||
    requiredQuantity < 1 ||
    requiredQuantity > 1000
  ) {
    fail("Required quantity must be between 1 and 1000.")
  }

  const contactInput = body.contactNumber

  if (typeof contactInput !== "string") {
    fail("Contact number is required.")
  }

  const contactNumber = contactInput.trim()

  if (contactNumber.length < 6 || contactNumber.length > 30) {
    fail("Contact number must be between 6 and 30 characters.")
  }

  const addressInput = body.deliveryAddress

  if (typeof addressInput !== "string") {
    fail("Delivery address is required.")
  }

  const deliveryAddress = addressInput.trim()

  if (deliveryAddress.length < 5 || deliveryAddress.length > 500) {
    fail("Delivery address must be between 5 and 500 characters.")
  }

  const notesInput = body.additionalNotes

  if (notesInput !== undefined && typeof notesInput !== "string") {
    fail("Additional notes must be text.")
  }

  const additionalNotes =
    typeof notesInput === "string" ? notesInput.trim() : ""

  if (additionalNotes.length > 2000) {
    fail("Additional notes must not exceed 2000 characters.")
  }

  const user = currentUser(req)

  const startAt = new Date(startAtValue)
  const endAt = new Date(endAtValue)

  const item = await equipmentById(equipmentId)

  if (item.status !== "approved") {
    fail("This equipment is not approved for rental.", 409)
  }

  if (item.ownerId === user.id) {
    fail("You cannot rent your own equipment.", 403)
  }

  if (startAt < new Date(Date.now() - 5 * 60_000)) {
    fail("Rental start date cannot be in the past.")
  }

  const amount = calculateRental(
    item.rentalPrice,
    item.rentalType as RentalType,
    startAt,
    endAt,
    requiredQuantity
  )

  const lockToken = new ObjectId().toHexString()

  const lock = await equipmentCollection().updateOne(
    {
      _id: item._id,
      $or: [
        { bookingLockUntil: { $lt: now() } },
        { bookingLockUntil: { $exists: false } },
      ],
    },
    {
      $set: {
        bookingLockToken: lockToken,
        bookingLockUntil: addMinutes(now(), 1),
      },
    }
  )

  if (!lock.matchedCount) {
    fail(
      "This equipment is receiving another booking. Please retry in a moment.",
      409,
      "BOOKING_LOCKED"
    )
  }

  try {
    await checkAvailability(
      item._id,
      startAt,
      endAt,
      requiredQuantity,
      Number(item.availableQuantity)
    )

    const booking = {
      equipmentId: item._id,
      equipmentName: item.name,
      equipmentImage: item.image,
      category: item.category,

      ownerId: item.ownerId,
      ownerEmail: item.ownerEmail,
      ownerName: item.ownerName,

      customerId: user.id,
      customerEmail: user.email,
      customerName: user.name,

      rentalType: item.rentalType,
      unitPrice: amount.unitPrice,
      rentalPeriods: amount.periods,
      durationDays: amount.days,

      startAt,
      endAt,
      requiredQuantity,

      contactNumber,
      deliveryAddress,
      additionalNotes,

      totalAmount: amount.total,
      currency: env.STRIPE_CURRENCY,

      paymentStatus: "unpaid",
      bookingStatus: "pending_payment",

      holdExpiresAt: addMinutes(
        now(),
        env.PAYMENT_HOLD_MINUTES
      ),

      createdAt: now(),
      updatedAt: now(),
    }

    const result = await bookingsCollection().insertOne(booking)

    await notify(
      item.ownerId,
      "booking_request",
      "New rental request",
      `${user.name} requested ${item.name}.`,
      "/dashboard/owner/rentals"
    )

    send(
      res,
      {
        ...booking,
        _id: result.insertedId,
        amountBreakdown: amount,
      },
      "Booking created. Continue to secure payment.",
      201
    )
  } finally {
    await equipmentCollection().updateOne(
      {
        _id: item._id,
        bookingLockToken: lockToken,
      },
      {
        $unset: {
          bookingLockToken: "",
          bookingLockUntil: "",
        },
      }
    )
  }
}))

app.get("/api/bookings/my", verifyToken, verifyRenter, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const page = Math.max(
    1,
    Number(req.query.page ?? 1) || 1
  )

  const limit = Math.min(
    100,
    Math.max(1, Number(req.query.limit ?? 20) || 20)
  )

  const [items, total] = await Promise.all([
    bookingsCollection()
      .find({ customerId: user.id })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray(),

    bookingsCollection().countDocuments({
      customerId: user.id,
    }),
  ])

  send(res, {
    items,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  })
}))


app.get("/api/bookings/:id", verifyToken, asyncHandler(async (req, res) => {
  const user = currentUser(req);

  const bookingId =
    typeof req.params.id === "string" ? req.params.id : ""

  const booking = await bookingById(bookingId)

  await assertBookingParticipant(booking, user)

  const payment = await paymentsCollection()
    .find({ bookingId: booking._id })
    .sort({ createdAt: -1 })
    .limit(5)
    .toArray()

  send(res, {
    ...booking,
    payments: payment,
  })
}))


app.post("/api/bookings/:id/cancel", verifyToken, asyncHandler(async (req, res) => {
  const user = currentUser(req);

  const bookingId =
    typeof req.params.id === "string" ? req.params.id : ""

  const booking = await bookingById(bookingId);

  if (
    booking.customerId !== user.id &&
    booking.ownerId !== user.id &&
    user.role !== "admin"
  ) {
    fail("You cannot cancel this booking.", 403);
  }

  if (
    ["completed", "cancelled", "expired"].includes(booking.bookingStatus)
  ) {
    fail("This booking can no longer be cancelled.", 409);
  }

  if (booking.paymentStatus === "paid") {
    fail(
      "A paid booking must be cancelled through the refund process by an admin.",
      409
    )
  }

  await bookingsCollection().updateOne(
    { _id: booking._id },
    {
      $set: {
        bookingStatus: "cancelled",
        cancelledAt: now(),
        updatedAt: now(),
      },
    }
  )


  await notify(
    booking.customerId,
    "booking_cancelled",
    "Booking cancelled",
    `${booking.equipmentName} booking was cancelled.`
  )


  await notify(
    booking.ownerId,
    "booking_cancelled",
    "Booking cancelled",
    `${booking.equipmentName} booking was cancelled.`
  )

  send(res, null, "Booking cancelled.")
}))

app.get("/api/owner/bookings", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const page = Math.max(
    1,
    Number(req.query.page ?? 1) || 1
  )

  const limit = Math.min(
    100,
    Math.max(1, Number(req.query.limit ?? 20) || 20)
  )

  const [items, total] = await Promise.all([
    bookingsCollection()
      .find({ ownerId: user.id })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .toArray(),

    bookingsCollection().countDocuments({
      ownerId: user.id,
    }),
  ])

  send(res, {
    items,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  })
}))

app.patch("/api/owner/bookings/:id/status", verifyToken, verifyOwner, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const rawBody: unknown = req.body

  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    fail("Invalid booking status request.")
  }

  const body = rawBody as AnyDoc
  const statusInput = body.status

  if (
    statusInput !== "in_progress" &&
    statusInput !== "completed" &&
    statusInput !== "cancelled"
  ) {
    fail("Invalid booking status.")
  }

  const status = statusInput

  const bookingId =
    typeof req.params.id === "string" ? req.params.id : ""

  const booking = await bookingById(bookingId)

  if (booking.ownerId !== user.id) {
    fail("You do not own this booking.", 403)
  }

  if (status === "in_progress" && booking.paymentStatus !== "paid") {
    fail("Only paid bookings can be marked in progress.", 409)
  }

  if (
    status === "completed" &&
    !["in_progress", "confirmed"].includes(booking.bookingStatus)
  ) {
    fail("Only active paid bookings can be completed.", 409)
  }

  if (status === "cancelled" && booking.paymentStatus === "paid") {
    fail("Paid booking cancellation requires admin refund handling.", 409)
  }

  await bookingsCollection().updateOne(
    { _id: booking._id },
    {
      $set: {
        bookingStatus: status,
        updatedAt: now(),
        ...(status === "completed" ? { completedAt: now() } : {}),
      },
    }
  )

  await notify(
    booking.customerId,
    "booking_status",
    "Rental status updated",
    `Your ${booking.equipmentName} rental is now ${status.replace("_", " ")}.`
  )

  const updatedBooking = await bookingsCollection().findOne({
    _id: booking._id,
  })

  send(
    res,
    updatedBooking,
    "Booking status updated."
  )
}))


app.post("/api/payments/checkout/:bookingId", verifyToken, verifyRenter, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const bookingId =
    typeof req.params.bookingId === "string"
      ? req.params.bookingId
      : ""

  if (!bookingId.trim()) {
    fail("Invalid booking ID.", 400, "INVALID_ID")
  }

  const booking = await bookingById(bookingId)

  if (booking.customerId !== user.id) {
    fail("You cannot pay for this booking.", 403);
  }

  if (
    booking.bookingStatus !== "pending_payment" ||
    booking.paymentStatus === "paid"
  ) {
    fail("This booking is not awaiting payment.", 409);
  }

  if (booking.holdExpiresAt && new Date(booking.holdExpiresAt) < now()) {
    fail(
      "The booking payment hold has expired. Please create a new booking.",
      409
    )
  }

  const existing = await paymentsCollection().findOne({
    bookingId: booking._id,
    status: "pending",
    checkoutUrl: { $exists: true },
  })

  if (
    existing?.checkoutUrl &&
    existing.expiresAt &&
    new Date(existing.expiresAt) > now()
  ) {
    return send(
      res,
      {
        checkoutUrl: existing.checkoutUrl,
        sessionId: existing.stripeSessionId,
        paymentId: existing._id,
      },
      "Existing checkout session returned."
    )
  }

  const paymentId = new ObjectId()

  const session = await createStripeCheckout({
    amount: Number(booking.totalAmount),
    currency: env.STRIPE_CURRENCY,

    productName: `GearHub rental: ${booking.equipmentName}`,
    description: `${booking.durationDays} day(s), quantity ${booking.requiredQuantity}`,

    customerEmail: user.email,

    metadata: {
      kind: "booking",
      bookingId: String(booking._id),
      paymentId: String(paymentId),
      customerId: user.id,
      ownerId: booking.ownerId,
    },

    idempotencyKey: `gearhub-booking-${booking._id}-${paymentId}`,
  })

  if (!session.url) {
    fail("Stripe did not return a checkout URL.", 502)
  }

  const payment = {
    _id: paymentId,
    bookingId: booking._id,
    customerId: user.id,
    ownerId: booking.ownerId,

    stripeSessionId: session.id,

    stripePaymentIntentId:
      typeof session.payment_intent === "string"
        ? session.payment_intent
        : null,

    checkoutUrl: session.url,

    amount: Number(booking.totalAmount),

    amountMinor: toStripeMinorUnits(
      Number(booking.totalAmount),
      env.STRIPE_CURRENCY
    ),

    currency: env.STRIPE_CURRENCY,
    status: "pending",
    purpose: "booking",

    createdAt: now(),

    expiresAt: session.expires_at
      ? new Date(session.expires_at * 1000)
      : addMinutes(now(), 30),
  }

  await paymentsCollection().insertOne(payment)

  await bookingsCollection().updateOne(
    { _id: booking._id },
    {
      $set: {
        stripeSessionId: session.id,
        updatedAt: now(),
      },
    }
  )

  send(
    res,
    {
      checkoutUrl: session.url,
      sessionId: session.id,
      paymentId,
    },
    "Stripe Checkout session created.",
    201
  )
}))


app.get("/api/payments/my", verifyToken, asyncHandler(async (req, res) => {
  const user = currentUser(req);

  const items = await paymentsCollection()
    .find({ customerId: user.id })
    .sort({ createdAt: -1 })
    .limit(100)
    .toArray()

  send(res, items)
}));


app.get("/api/payments/session/:sessionId", verifyToken, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const sessionId = req.params.sessionId

  if (typeof sessionId !== "string" || !sessionId.trim()) {
    fail("Invalid payment session ID.", 400)
  }

  const payment = await paymentsCollection().findOne({
    stripeSessionId: sessionId,
    customerId: user.id,
  })

  if (!payment) {
    return fail("Payment session not found.", 404)
  }

  send(res, {
    status: payment.status,
    amount: payment.amount,
    currency: payment.currency,
    bookingId: payment.bookingId,
  })
}))


app.get("/api/favorites", verifyToken, verifyRenter, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const favorites = await favoritesCollection()
    .find({ customerId: user.id })
    .sort({ createdAt: -1 })
    .toArray()

  const ids = favorites.map((item) => item.equipmentId)

  const items = ids.length
    ? await equipmentCollection().find({ _id: { $in: ids } }).toArray()
    : []

  send(res, items)
}))

app.post("/api/favorites/:equipmentId", verifyToken, verifyRenter, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const equipmentId =
    typeof req.params.equipmentId === "string"
      ? req.params.equipmentId
      : ""

  if (!equipmentId.trim()) {
    fail("Invalid equipment ID.", 400, "INVALID_ID")
  }
  const item = await equipmentById(equipmentId)

  if (item.status !== "approved") {
    fail("Equipment is not available.", 404)
  }

  await favoritesCollection().updateOne(
    {
      customerId: user.id,
      equipmentId: item._id,
    },
    {
      $setOnInsert: {
        customerId: user.id,
        equipmentId: item._id,
        createdAt: now(),
      },
    },
    { upsert: true }
  )

  send(res, null, "Added to favorites.", 201)
}));

app.delete("/api/favorites/:equipmentId", verifyToken, verifyRenter, asyncHandler(async (req, res) => {
  const user = currentUser(req)

  const equipmentId =
    typeof req.params.equipmentId === "string"
      ? req.params.equipmentId
      : ""

  if (!equipmentId.trim()) {
    fail("Invalid equipment ID.", 400, "INVALID_ID")
  }

  await favoritesCollection().deleteOne({
    customerId: user.id,
    equipmentId: asObjectId(equipmentId, "equipment id"),
  })

  send(res, null, "Removed from favorites.")
}))



app.get("/health", asyncHandler(async (_req, res) => {
  await db.command({ ping: 1 });

  send(
    res,
    {
      status: "ok",
      database: "connected",
      stripeConfigured: Boolean(stripe),
      time: now().toISOString(),
    },
    "GearHub API is healthy"
  )
}))


app.all("/api/auth/*", authLimiter, (req, res, next) => {
  if (!betterAuthHandler) {
    return next(
      new AppError(
        "Authentication service is starting. Retry shortly.",
        503
      )
    )
  }

  try {
    betterAuthHandler(req, res)
  } catch (error) {
    next(error)
  }
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
