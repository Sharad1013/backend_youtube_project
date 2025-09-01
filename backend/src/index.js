import express from "express"
import dotenv from "dotenv"
import connectDb from "./db/index.js"

dotenv.config({})

const app = express()
connectDb()