import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();app.use(cors({
  origin: function (origin, callback) {
    if (origin && origin !== process.env.CORS_ORIGIN) {
      console.log('Blocked CORS origin: ', origin);  // Log blocked origin
      callback(new Error('CORS Not Allowed'), false);
    } else {
      callback(null, true);
    }
  },
  credentials: true
}));

app.use(express.json({ limit: "40kb" }));
app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.static("public"));
app.use(cookieParser());
import approuter from "./routes/user.router.js";
import userData from "./routes/usrData.router.js";
app.use("/", approuter);
app.use("/api/", userData);
app.use((err, req, res, next) => {
  console.error("Unexpected error:", err);
  res.status(500).send("Internal Server Error this is due to me");
});
export default app;
