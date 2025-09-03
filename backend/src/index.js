import dotenv from "dotenv"
dotenv.config({})

import connectDb from "./db/index.js"
import app from "./app.js"


app.on("error", (error) => {
    console.log(`MONGODB Connection Failed: ${error}`)
})

connectDb().then(() => {
    app.listen(process.env.PORT || 8000, () => {
        console.log(`PORT is listening on http://localhost:${process.env.PORT || 8000}`)
    })
}).catch((err) => {
    console.log(`MONGO DB Connection FAILED!! :  ${err}`)
})