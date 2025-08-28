const { Router } = require("express")
const { deleteMonto, updateMonto, createMonto, getMontoById, getAllMontos } = require("../controllers/montoController")

const router = Router()

router.get("/monto", getAllMontos)
router.get("/monto/:id", getMontoById)
router.post("/monto",createMonto)
router.delete("/monto/:id", deleteMonto)
router.patch("/monto/:id", updateMonto)

module.exports={
    router_monto: router
}

