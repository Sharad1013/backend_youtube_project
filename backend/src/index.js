import express from "express"
import dotenv from "dotenv"
import connectDb from "./db/index.js"
import app from "./app.js"

dotenv.config({})

connectDb().then(() => {
    app.on("error", (error) => {
        console.log(`MONGODB Connection Failed: ${error}`)
    })
    app.listen(process.env.PORT || 8000, () => {
        console.log(`PORT is listening on http://localhost:${process.env.PORT || 8000}`)
    })
}).catch((err) => {
    console.log(`MONGO DB Connection FAILED!! :  ${err}`)
})