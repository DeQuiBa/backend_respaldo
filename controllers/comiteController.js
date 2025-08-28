const { pool } = require("../config/db")


const getAllComite = async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre FROM comite ORDER BY nombre');
        return res.status(200).json({ comites: result.rows });

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al obtener los comites" })
    }
}

const getComiteById = async (req, res) => {
    try {

        const { id } = req.params
        const result = await pool.query("SELECT * FROM comite WHERE id=$1", [id])
        if (result.rows.length === 0) return res.status(404).json({ error: "comite no encontrado" })
        return res.json(result.rows[0])

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al obtener comite por id" })

    }
}

const createComite = async (req, res) => {
    try {

        const { nombre, epoca } = req.body

        // field no empty
        if (!nombre || !epoca) {
            return res.status(400).json({ error: "Todos los campos obligatorios deben estar completos." });
        }

        // verificar duplicado
        const exists = await pool.query(
            "SELECT 1 FROM comite WHERE nombre = $1 LIMIT 1",
            [nombre]
        );
        if (exists.rowCount > 0) {
            return res.status(400).json({ error: "Ya existe un comité con ese nombre." });
        }

        // insertar
        const result = await pool.query(
            `INSERT INTO comite (nombre, epoca) 
             VALUES($1,$2)
             RETURNING *`,
            [nombre, epoca]
        )

        const data = result.rows[0]

        return res.json({ message: "Comite creado correctamente", data })

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al crear comite" })
    }
}

const deleteComite = async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query("SELECT * FROM comite WHERE id=$1", [id])
        if (result.rows.length === 0) return res.status(404).json({ error: "comite no encontrado" })

        await pool.query("DELETE FROM comite WHERE id = $1", [id]);
        return res.json({ message: "Comite eliminado" });

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al eliminar comite" })
    }
}


module.exports = {
    getAllComite,
    getComiteById,
    createComite,
    deleteComite
}


