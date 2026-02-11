// database.js - Base de datos completa con PostgreSQL

const { Sequelize, DataTypes } = require('sequelize');
const crypto = require('crypto');

// Conexión a la base de datos
const sequelize = new Sequelize(process.env.DATABASE_URL || 'sqlite:./database.sqlite', {
  dialect: process.env.DATABASE_URL ? 'postgres' : 'sqlite',
  logging: false,
  dialectOptions: process.env.DATABASE_URL ? {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  } : {}
});

// ============================================================================
// MODELO: Shops (Tiendas instaladas)
// ============================================================================

const Shop = sequelize.define('Shop', {
  shop: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false,
    comment: 'Dominio de la tienda (ej: mi-tienda.myshopify.com)'
  },
  accessToken: {
    type: DataTypes.STRING,
    allowNull: false,
    comment: 'Access token de Shopify OAuth'
  },
  scope: {
    type: DataTypes.STRING,
    comment: 'Scopes otorgados por la tienda'
  },
  installedAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  uninstalledAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  }
}, {
  tableName: 'shops',
  timestamps: true
});

// ============================================================================
// MODELO: Extension Access Keys (Para la extensión Chrome)
// ============================================================================

const ExtensionKey = sequelize.define('ExtensionKey', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  shop: {
    type: DataTypes.STRING,
    allowNull: false,
    references: {
      model: Shop,
      key: 'shop'
    }
  },
  accessKey: {
    type: DataTypes.STRING(255),
    allowNull: false,
    comment: 'Access key para la extensión (sk_...)'
  },
  name: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Nombre descriptivo del key (ej: "Mi Computadora")'
  },
  lastUsedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'extension_keys',
  timestamps: true,
  indexes: [
    {
      unique: true,
      fields: ['accessKey'],
      name: 'extension_keys_access_key_unique'
    }
  ]
});

// ============================================================================
// MODELO: Sender Configs (Configuración de remitente por tienda)
// ============================================================================

const SenderConfig = sequelize.define('SenderConfig', {
  shop: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false,
    references: {
      model: Shop,
      key: 'shop'
    }
  },
  senderIdentificationType: {
    type: DataTypes.STRING,
    defaultValue: '1',
    comment: '1=Cédula, 2=DIMEX, 3=Pasaporte'
  },
  senderId: {
    type: DataTypes.STRING,
    allowNull: true
  },
  senderName: {
    type: DataTypes.STRING,
    allowNull: true
  },
  senderPhone: {
    type: DataTypes.STRING,
    allowNull: true
  },
  senderMail: {
    type: DataTypes.STRING,
    allowNull: true
  },
  provinciaSender: {
    type: DataTypes.STRING,
    defaultValue: '1'
  },
  cantonSender: {
    type: DataTypes.STRING,
    defaultValue: '1'
  },
  distritoSender: {
    type: DataTypes.STRING,
    defaultValue: '1'
  },
  senderPostalCode: {
    type: DataTypes.STRING,
    allowNull: true
  },
  senderDirection: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  tableName: 'sender_configs',
  timestamps: true
});

// Relaciones
Shop.hasMany(ExtensionKey, { foreignKey: 'shop', sourceKey: 'shop' });
ExtensionKey.belongsTo(Shop, { foreignKey: 'shop', targetKey: 'shop' });

Shop.hasOne(SenderConfig, { foreignKey: 'shop', sourceKey: 'shop' });
SenderConfig.belongsTo(Shop, { foreignKey: 'shop', targetKey: 'shop' });

// ============================================================================
// FUNCIONES DE BASE DE DATOS
// ============================================================================

// Inicializar base de datos
async function initDatabase() {
  try {
    await sequelize.authenticate();
    console.log('✓ Conexión a base de datos establecida');

    await sequelize.sync({ alter: true });
    console.log('✓ Modelos sincronizados');

    return true;
  } catch (error) {
    console.error('✗ Error conectando a la base de datos:', error);
    return false;
  }
}

// ============================================================================
// SHOPS
// ============================================================================

async function saveShopSession(shop, accessToken, scope = null) {
  try {
    const [shopRecord, created] = await Shop.upsert({
      shop,
      accessToken,
      scope,
      installedAt: new Date(),
      uninstalledAt: null,
      isActive: true
    });

    console.log(`✓ Tienda ${created ? 'instalada' : 'actualizada'}: ${shop}`);
    return shopRecord;
  } catch (error) {
    console.error('Error guardando tienda:', error);
    throw error;
  }
}

async function getShopSession(shop) {
  try {
    const shopRecord = await Shop.findOne({
      where: {
        shop,
        isActive: true
      }
    });

    return shopRecord;
  } catch (error) {
    console.error('Error obteniendo tienda:', error);
    return null;
  }
}

async function deleteShopSession(shop) {
  try {
    await Shop.update(
      {
        isActive: false,
        uninstalledAt: new Date()
      },
      {
        where: { shop }
      }
    );

    // Desactivar también todos los access keys
    await ExtensionKey.update(
      { isActive: false },
      { where: { shop } }
    );

    console.log(`✓ Tienda desinstalada: ${shop}`);
  } catch (error) {
    console.error('Error desinstalando tienda:', error);
  }
}

async function getActiveShopsCount() {
  try {
    return await Shop.count({
      where: { isActive: true }
    });
  } catch (error) {
    console.error('Error contando tiendas:', error);
    return 0;
  }
}

// ============================================================================
// EXTENSION ACCESS KEYS
// ============================================================================

// Generar un access key único
function generateAccessKey() {
  return 'sk_' + crypto.randomBytes(32).toString('hex');
}

// Crear un nuevo access key para una tienda
async function createExtensionKey(shop, name = null) {
  try {
    // Verificar que la tienda existe
    const shopRecord = await getShopSession(shop);
    if (!shopRecord) {
      throw new Error('Shop not found');
    }

    const accessKey = generateAccessKey();

    const key = await ExtensionKey.create({
      shop,
      accessKey,
      name,
      isActive: true
    });

    console.log(`✓ Access key creado para ${shop}`);
    return key;
  } catch (error) {
    console.error('Error creando access key:', error);
    throw error;
  }
}

// Validar un access key y obtener la tienda asociada
async function validateExtensionKey(accessKey) {
  try {
    const key = await ExtensionKey.findOne({
      where: {
        accessKey,
        isActive: true
      },
      include: [{
        model: Shop,
        where: { isActive: true }
      }]
    });

    if (key) {
      // Actualizar último uso
      await key.update({ lastUsedAt: new Date() });

      return {
        shop: key.shop,
        accessToken: key.Shop.accessToken
      };
    }

    return null;
  } catch (error) {
    console.error('Error validando access key:', error);
    return null;
  }
}

// Obtener todos los access keys de una tienda
async function getShopExtensionKeys(shop) {
  try {
    return await ExtensionKey.findAll({
      where: {
        shop,
        isActive: true
      },
      order: [['createdAt', 'DESC']]
    });
  } catch (error) {
    console.error('Error obteniendo access keys:', error);
    return [];
  }
}

// Borrar TODOS los datos de una tienda
async function deleteShopData(shop) {
  try {
    console.log(`🗑️ Deleting all data for shop: ${shop}`);

    // Borrar todos los access keys de la tienda
    const deletedKeys = await ExtensionKey.destroy({
      where: { shop }
    });

    // Borrar todas las sessions de la tienda
    const deletedSessions = await Session.destroy({
      where: { shop }
    });

    // Borrar configuración de sender (si existe)
    const deletedSenderConfigs = await SenderConfig.destroy({
      where: { shop }
    });

    console.log(`✅ Shop data deleted: ${deletedKeys} keys, ${deletedSessions} sessions, ${deletedSenderConfigs} configs`);

    return {
      success: true,
      deleted: {
        keys: deletedKeys,
        sessions: deletedSessions,
        senderConfigs: deletedSenderConfigs
      }
    };

  } catch (error) {
    console.error('❌ Error deleting shop data:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Revocar un access key
async function revokeExtensionKey(accessKey, shop) {
  try {
    await ExtensionKey.update(
      { isActive: false },
      {
        where: {
          accessKey,
          shop
        }
      }
    );

    console.log(`✓ Access key revocado: ${accessKey.substring(0, 10)}...`);
  } catch (error) {
    console.error('Error revocando access key:', error);
  }
}

// ============================================================================
// SENDER CONFIG
// ============================================================================

async function saveSenderConfig(shop, config) {
  try {
    const [senderConfig, created] = await SenderConfig.upsert({
      shop,
      ...config
    });

    console.log(`✓ Configuración ${created ? 'creada' : 'actualizada'} para ${shop}`);
    return senderConfig;
  } catch (error) {
    console.error('Error guardando configuración:', error);
    throw error;
  }
}

async function getSenderConfig(shop) {
  try {
    return await SenderConfig.findOne({
      where: { shop }
    });
  } catch (error) {
    console.error('Error obteniendo configuración:', error);
    return null;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  sequelize,
  Shop,
  ExtensionKey,
  SenderConfig,

  // Funciones generales
  initDatabase,

  // Shops
  saveShopSession,
  getShopSession,
  deleteShopSession,
  getActiveShopsCount,
  deleteShopData,

  // Extension Keys
  generateAccessKey,
  createExtensionKey,
  validateExtensionKey,
  getShopExtensionKeys,
  revokeExtensionKey,

  // Sender Config
  saveSenderConfig,
  getSenderConfig
};
