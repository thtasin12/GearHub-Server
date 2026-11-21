import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";

dotenv.config();

const env = {
  PORT: Number(process.env.PORT ?? 5000),

  MONGODB_URI:
    process.env.MONGODB_URI ?? "mongodb://127.0.0.1:27017",

  MONGODB_DB_NAME:
    process.env.MONGODB_DB_NAME ?? "gearhub",
};

const app = express();

//Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
  })
);


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
