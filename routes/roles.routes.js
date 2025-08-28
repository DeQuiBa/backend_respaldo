const { Router } = require("express")
const { getAllRoles, createRol, deleteRol } = require("../controllers/rolController")

const router = Router()

router.get("/rol", getAllRoles)
router.post("/rol", createRol)
router.delete("/rol/:id", deleteRol)

module.exports = {
    router_roles: router
}
