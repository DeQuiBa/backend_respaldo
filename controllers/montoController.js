const { pool } = require("../config/db")


const getAllMontos = async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM monto")
        return res.status(200).json(result.rows)

    } catch (err) {
        console.log(err)
        return res.status(500).json({ error: " Error al obtener montos" })

    }
}

const getMontoById = async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query("SELECT * FROM monto WHERE id=$1", [id])
        if (result.rows.length === 0) return res.status(404).json({ error: "Monto no encontrado" })
        return res.json(result.rows[0])
    } catch (err) {
        console.error(err)
        return res.status(500).json({ error: "Error al obtener monto" })
    }
}


const createMonto = async (req, res) => {
    try {

        const { fk_usuario, fecha, tipo_de_cuenta, actividad, codigo, voucher, cantidad } = req.body

        // no permitir empty
        if (fk_usuario == null || !fecha || !tipo_de_cuenta || !actividad || !cantidad) {
            return res.status(400).json({ error: "Todos los campos obligatorios deben estar completos." });
        }

        // validacion de tipo de cuenta
        if (!["Ingreso", "Egreso"].includes(tipo_de_cuenta)) {
            return res.status(400).json({ error: "Tipo de cuenta inválido. Debe ser 'Ingreso' o 'Egreso'." });
        }

        // insertar
        const result = await pool.query(
            `INSERT INTO monto (fk_usuario, fecha, tipo_de_cuenta, actividad, codigo, voucher , cantidad) 
             VALUES($1,$2 ,$3,$4,$5 ,$6,$7)
             RETURNING *`,
            [fk_usuario, fecha, tipo_de_cuenta, actividad, codigo || null, voucher || null, cantidad]
        )

        const data = result.rows[0]

        return res.json({ message: "Monto creado correctamente", data })
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Error al crear monto" });
    }
}

const updateMonto = async (req, res) => {
    try {
        const { id } = req.params;
        const { fk_usuario, fecha, tipo_de_cuenta, actividad, codigo, voucher, cantidad } = req.body;

        if (tipo_de_cuenta && !["Ingreso", "Egreso"].includes(tipo_de_cuenta)) {
            return res.status(400).json({ error: "Tipo de cuenta inválido" });
        }

        const result = await pool.query(
            `UPDATE monto SET
                fk_usuario   = COALESCE($1, fk_usuario),
                fecha        = COALESCE($2, fecha),
                tipo_de_cuenta = COALESCE($3, tipo_de_cuenta),
                actividad    = COALESCE($4, actividad),
                codigo       = COALESCE($5, codigo),
                voucher      = COALESCE($6, voucher),
                cantidad     = COALESCE($7, cantidad)
            WHERE id = $8
            RETURNING *`,
            [fk_usuario, fecha, tipo_de_cuenta, actividad, codigo, voucher, cantidad, id]
        );

        if (result.rows.length === 0) return res.status(404).json({ error: "Monto no encontrado" });
        return res.json({ message: "Monto actualizado parcialmente", data: result.rows[0] });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Error al editar monto" });
    }
}

const deleteMonto = async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query("SELECT * FROM monto WHERE id=$1", [id])
        if (result.rows.length === 0) return res.status(404).json({ error: "Monto no encontrado" })

        await pool.query("DELETE FROM monto WHERE id = $1", [id]);
        return res.json({ message: "Monto eliminado" });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Error al eliminar monto" });

    }
}

module.exports = {
    getAllMontos,
    getMontoById,
    createMonto,
    updateMonto,
    deleteMonto
}