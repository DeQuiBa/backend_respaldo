const { Router } = require("express")
const { getAllComite, getComiteById, createComite, deleteComite } = require("../controllers/comiteController")

const router = Router()
/**
 * @swagger
 * /comite:
 *   get:
 *     summary: Obtener todos los comites
 *     tags: [Comite]
 *     responses:
 *       200:
 *         description: Lista de los comites del sistema
 */
router.get("/comite", getAllComite)

/**
 * @swagger
 * /comite/{id}:
 *   get:
 *     summary: Obtener un comité por ID
 *     tags: [Comite]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Comité encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 nombre:
 *                   type: string
 *                 epoca:
 *                   type: string
 *       404:
 *         description: Comité no encontrado
 */
router.get("/comite/:id", getComiteById)

/**
 * @swagger
 * /comite:
 *   post:
 *     summary: Crear un nuevo comité
 *     tags: [Comite]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nombre
 *               - epoca
 *             properties:
 *               nombre:
 *                 type: string
 *               epoca:
 *                 type: number
 *     responses:
 *       200:
 *         description: Comité creado correctamente
 *       400:
 *         description: Datos incompletos o comité duplicado
 */
router.post("/comite", createComite)


/**
 * @swagger
 * /comite/{id}:
 *   delete:
 *     summary: Eliminar un comité por ID
 *     tags: [Comite]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Comité eliminado
 *       404:
 *         description: Comité no encontrado
 */
router.delete("/comite/:id", deleteComite)

module.exports = {
    router_comite: router
}

