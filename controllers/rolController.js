const { pool } = require("../config/db")

const getAllRoles = async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM roles ORDER BY nombre_rol');
        return res.json({ roles: result.rows });
    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al obtener los roles" })
    }
}

const createRol = async (req, res) => {
    try {

        const { nombre_rol, descripcion } = req.body

        // verificar duplicado
        const exists = await pool.query(
            "SELECT 1 FROM roles WHERE nombre_rol = $1 LIMIT 1",
            [nombre_rol]
        );
        if (exists.rowCount > 0) {
            return res.status(400).json({ error: "Ya existe un rol con ese nombre." });
        }

        // insertar
        const result = await pool.query(
            `INSERT INTO roles (nombre_rol,descripcion) 
             VALUES($1,$2)
             RETURNING *`,
            [nombre_rol, descripcion || null]
        )

        const data = result.rows[0]

        return res.json({ message: "Rol creado correctamente", data })

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al crear el rol" })
    }
}

const deleteRol = async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query("SELECT * FROM roles WHERE id=$1", [id])
        if (result.rows.length === 0) return res.status(404).json({ error: "rol no encontrado" })

        await pool.query("DELETE FROM roles WHERE id = $1", [id]);
        return res.json({ message: "Rol eliminado" });

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al eliminar el rol" })
    }
}

module.exports = {
    getAllRoles,
    createRol,
    deleteRol
}