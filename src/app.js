import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

const allowedOrigins = [
  process.env.CORS_ORIGIN || "https://abmarineai.vercel.app",
];

app.use(express.json({ limit: "40kb" }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: "20kb" }));
app.use(express.static("public"));

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("Blocked CORS origin: ", origin);
        callback(new Error("CORS Not Allowed"), false);
      }
    },
    credentials: true,
  })
);
// app.use((req, res, next) => {
//   const origin = req.headers.origin;
//   if (allowedOrigins.includes(origin)) {
//     res.header("Access-Control-Allow-Origin", origin);
//   }
//   res.header("Access-Control-Allow-Credentials", "true");
//   next();
// });

// app.use(express.urlencoded({ extended: true, limit: "20kb" }));
// app.use(express.static("public"));
import approuter from "./routes/user.router.js";
import userData from "./routes/usrData.router.js";
import router from "./routes/subscription.route.js";
app.use("/", approuter);
app.use("/api/", userData);
app.use("/sub", router);
app.use((err, req, res, next) => {
  console.error("Unexpected error:", err);
  res.status(500).send("Internal Server Error this is due to me");
});
export default app;
