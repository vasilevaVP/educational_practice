const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const { Sequelize, DataTypes } = require("sequelize");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");

const app = express();
const port = 3000;

// Настройка базы данных SQLite
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: "db.sqlite",
});

// Модель роли
const Role = sequelize.define(
  "Role",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  { timestamps: false }
);

// Модель пользователей
const User = sequelize.define(
  "User",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    fullName: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: { msg: "ФИО не может быть пустым" },
        len: {
          args: [3, 100],
          msg: "ФИО должно быть от 3 до 100 символов",
        },
      },
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: { msg: "Некорректный формат email" },
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: {
          args: [6, 100],
          msg: "Пароль должен быть от 6 до 100 символов",
        },
      },
    },
    roleId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: Role,
        key: "id",
      },
    },
  },
  { timestamps: false }
);

// Модель Development
const Development = sequelize.define(
  "Development",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "development_id",
    },
    title: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
    },
    file_path: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    preview: {
      type: DataTypes.STRING,
    },
    categoryId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "category_id",
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "user_id",
      references: {
        model: "users",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
  }
);

// Модель Category
const Category = sequelize.define(
  "Category",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "category_id",
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  {
    timestamps: false,
    tableName: "categories",
  }
);

// Модель Tag
const Tag = sequelize.define(
  "Tag",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "tag_id",
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  {
    timestamps: false,
    tableName: "tags",
  }
);

// Модель DownloadHistory
const DownloadHistory = sequelize.define(
  "DownloadHistory",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "download_history_id",
    },
    download_date: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: Sequelize.NOW,
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "user_id",
      references: {
        model: "users",
        key: "id",
      },
    },
    developmentId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "development_id",
      references: {
        model: "developments",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
    tableName: "download_history",
  }
);

// Модель Profile
const Profile = sequelize.define(
  "Profile",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
      field: "profile_id",
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: "user_id",
      references: {
        model: "users",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
    tableName: "profiles",
  }
);

// Модель Subscription
const Subscription = sequelize.define(
  "Subscription",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
      },
    },
  },
  {
    timestamps: true,
    tableName: "subscriptions",
  }
);

// Связующая таблица DevelopmentTags для Many-to-Many
const DevelopmentTags = sequelize.define(
  "DevelopmentTags",
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true,
    },
    developmentId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "developments",
        key: "id",
      },
    },
    tagId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "tags",
        key: "id",
      },
    },
  },
  {
    timestamps: false,
    tableName: "development_tags",
  }
);

// Определение связей
Role.hasMany(User, { foreignKey: "roleId" });
User.belongsTo(Role, { foreignKey: "roleId" });

User.hasMany(Development, { foreignKey: "userId", as: "developments" });
Development.belongsTo(User, { foreignKey: "userId", as: "user" });

User.hasMany(DownloadHistory, {
  foreignKey: "userId",
  as: "downloadHistory",
});

Category.hasMany(Development, {
  foreignKey: "categoryId",
  as: "developments",
});
Development.belongsTo(Category, {
  foreignKey: "categoryId",
  as: "category",
});
Development.hasMany(DownloadHistory, {
  foreignKey: "development_id",
  as: "downloadHistory", // Изменяем алиас с "downloads" на "downloadHistory"
});

// Many-to-Many между Development и Tag
Development.belongsToMany(Tag, {
  through: DevelopmentTags,
  foreignKey: "developmentId",
  otherKey: "tagId",
  as: "tags",
});

Tag.belongsToMany(Development, {
  through: DevelopmentTags,
  foreignKey: "tagId",
  otherKey: "developmentId",
  as: "developments",
});

// Profile
User.hasOne(Profile, { foreignKey: "userId", as: "profile" });
Profile.belongsTo(User, { foreignKey: "userId", as: "user" });

// DownloadHistory
Profile.hasMany(DownloadHistory, {
  foreignKey: "userId",
  as: "downloadHistory",
});

DownloadHistory.belongsTo(Profile, {
  foreignKey: "userId",
  as: "profile",
});
DownloadHistory.belongsTo(User, {
  foreignKey: "userId",
  as: "user",
});
DownloadHistory.belongsTo(Development, {
  foreignKey: "development_id",
  as: "development",
});

// Синхронизация базы данных и создание админа при первом запуске
sequelize
  .sync({ force: false })
  .then(async () => {
    console.log("База данных синхронизирована");

    // Создаем роли если их еще нет
    const userRole = await Role.findOrCreate({
      where: { name: "user" },
      defaults: { name: "user" },
    });
    const adminRole = await Role.findOrCreate({
      where: { name: "admin" },
      defaults: { name: "admin" },
    });

    //Проверка есть ли пользователи в бд
    const usersCount = await User.count();

    // Если нет пользователей - создаем админа
    if (usersCount === 0) {
      const hashedPassword = await bcrypt.hash("admin", 10);
      await User.create({
        fullName: "Admin",
        email: "admin@example.com",
        password: hashedPassword,
        roleId: adminRole[0].id,
      });
      console.log("Администратор создан");
    }
  })
  .catch((err) => console.error(err));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // Middleware для обработки JSON
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(
  session({
    secret: "secret-key",
    resave: true,
    saveUninitialized: false,
  })
);

// Проверка авторизации
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Проверка роли
function hasRole(roleName) {
  return async (req, res, next) => {
    if (req.session.user) {
      const user = await User.findByPk(req.session.user.id, { include: Role });
      if (user && user.Role.name === roleName) {
        next();
      } else {
        res.status(403).send("Доступ запрещен");
      }
    } else {
      res.redirect("/login");
    }
  };
}

// Маршруты

// Главная страница
app.get("/", (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === "admin") {
      res.redirect("/admin");
    } else {
      res.redirect("/profile");
    }
  } else {
    res.redirect("/index");
  }
});

// Роут для главной страницы
app.get("/index", async (req, res) => {
  res.render("index", { user: req.session.user });
});

// Роут для обработки подписки на рассылку
app.post("/subscribe", async (req, res) => {
  const { email } = req.body;
  try {
    const existingSubscription = await Subscription.findOne({
      where: { email },
    });
    if (existingSubscription) {
      return res
        .status(400)
        .json({ message: "Этот email уже подписан на рассылку." });
    }
    await Subscription.create({ email: email.trim() });
    res.json({ message: "Вы успешно подписались на рассылку!" });
  } catch (error) {
    console.error("Ошибка при подписке на рассылку:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Роут для страницы каталога
app.get("/catalog", async (req, res) => {
  try {
    const developments = await Development.findAll({
      include: [
        {
          model: Category,
          as: "category",
        },
        {
          model: Tag,
          as: "tags",
          through: { attributes: [] }, // Убираем лишние данные из промежуточной таблицы
        },
      ],
    });

    res.render("catalog", {
      user: req.session.user,
      developments: developments.map((dev) => dev.get({ plain: true })),
      categories: await Category.findAll(),
      tags: await Tag.findAll(),
    });
  } catch (error) {
    console.error("Ошибка:", error);
    res.status(500).send("Ошибка сервера");
  }
});
// Роут для страницы подробнее для разработки
app.get("/card", isAuthenticated, async (req, res) => {
  const developmentId = req.query.id;
  try {
    const development = await Development.findByPk(developmentId, {
      include: [
        { model: Category, as: "category" },
        { model: Tag, through: DevelopmentTags, as: "tags" },
      ],
    });
    if (!development) {
      return res.status(404).send("Разработка не найдена");
    }
    res.render("card", {
      user: req.session.user,
      development: development,
    });
  } catch (error) {
    console.error("Ошибка при получении карточки:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для скачивания файлов
app.get("/download/:id", isAuthenticated, async (req, res) => {
  try {
    const developmentId = req.params.id;
    const userId = req.session.user.id;

    // Находим разработку
    const development = await Development.findByPk(developmentId);
    if (!development) {
      return res.status(404).send("Разработка не найдена");
    }

    // Записываем в историю скачиваний
    await DownloadHistory.create({
      userId: userId,
      developmentId: development.id,
    });

    // Отправляем файл для скачивания
    const filePath = path.join(__dirname, "public", development.file_path);
    res.download(filePath);
  } catch (error) {
    console.error("Ошибка при скачивании:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для страницы о нас
app.get("/about_us", async (req, res) => {
  res.render("about_us", { user: req.session.user });
});

// Роут для страницы регистрации
app.get("/register", async (req, res) => {
  res.render("register", { user: req.session.user, error: null });
});

// Роут для страницы добавления разработки
app.get("/addDevelopment", isAuthenticated, async (req, res) => {
  try {
    const categories = await Category.findAll();
    const tags = await Tag.findAll();
    res.render("addDevelopment", {
      user: req.session.user,
      error: null,
      categories,
      tags,
    });
  } catch (error) {
    console.error("Ошибка при загрузке формы:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для получения разработок пользователя
app.get("/user/developments/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;

  try {
    const developments = await Development.findAll({
      where: { userId },
    });
    res.json(developments);
  } catch (error) {
    console.error("Ошибка при получении разработок пользователя:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для получения истории скачиваний пользователя
app.get("/user/downloads/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;

  try {
    const downloads = await DownloadHistory.findAll({
      where: { userId },
      include: [{ model: Development, as: "development" }],
    });
    res.json(downloads);
  } catch (error) {
    console.error("Ошибка при получении истории скачиваний:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Админ панель
app.get("/admin", isAuthenticated, hasRole("admin"), async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ["id", "fullName", "email"],
      order: [["fullName", "ASC"]],
      where: {
        "$Role.name$": {
          [Sequelize.Op.not]: "admin",
        },
      },
      include: [
        {
          model: Role,
          required: true,
          attributes: [],
        },
      ],
    });
    const userCount = users.length;
    const categories = await Category.findAll();
    const tags = await Tag.findAll();
    res.render("admin", {
      user: req.session.user,
      users,
      userCount,
      categories,
      tags,
    });
  } catch (error) {
    console.error("Ошибка получения списка пользователей:", error);
    res.status(500).send("Ошибка сервера");
  }
});
// Удаление тега
app.post(
  "/admin/delete/tag/:id",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const tagId = req.params.id;

      // Удаляем связи с разработками
      await DevelopmentTags.destroy({ where: { tagId } });

      // Удаляем сам тег
      await Tag.destroy({ where: { id: tagId } });

      res.json({ success: true });
    } catch (error) {
      console.error("Ошибка при удалении тега:", error);
      res.status(500).json({ error: "Ошибка сервера" });
    }
  }
);

// Удаление категории
app.post(
  "/admin/delete/category/:id",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const categoryId = req.params.id;

      // Обновляем разработки, убирая категорию (можно установить значение по умолчанию)
      await Development.update({ categoryId: null }, { where: { categoryId } });

      // Удаляем саму категорию
      await Category.destroy({ where: { id: categoryId } });

      res.json({ success: true });
    } catch (error) {
      console.error("Ошибка при удалении категории:", error);
      res.status(500).json({ error: "Ошибка сервера" });
    }
  }
);

// Настройка multer для обработки загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "public", "uploads"));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "video/mp4",
  ];

  const allowedExtensions = [
    ".jpeg",
    ".jpg",
    ".png",
    ".pdf",
    ".docx",
    ".ppt",
    ".pptx",
    ".mp4",
  ];

  const mimeType = file.mimetype.toLowerCase();
  const extension = path.extname(file.originalname).toLowerCase();

  if (
    !allowedMimeTypes.includes(mimeType) ||
    !allowedExtensions.includes(extension)
  ) {
    return cb("Ошибка: Неправильный тип файла.", false);
  }

  if (file.size > 10 * 1024 * 1024) {
    return cb("Ошибка: Файл слишком большой. Максимальный размер - 10 МБ.");
  }

  cb(null, true);
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 100 * 1024 * 1024 },
});

// AJAX endpoints для добавления
app.post(
  "/admin/add/tag",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    const { name } = req.body;
    if (!name || name.trim() === "") {
      return res.status(400).send({ error: "Имя тега не может быть пустым." });
    }
    try {
      const existingTag = await Tag.findOne({ where: { name: name.trim() } });
      if (existingTag) {
        return res
          .status(400)
          .send({ error: "Тег с таким именем уже существует." });
      }
      const tag = await Tag.create({ name: name.trim() });
      res.status(201).send({ success: true, tag });
    } catch (error) {
      console.error("Ошибка при добавлении тега:", error);
      res.status(500).send({ error: "Ошибка сервера." });
    }
  }
);

app.post(
  "/admin/add/category",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    const { name } = req.body;
    if (!name || name.trim() === "") {
      return res
        .status(400)
        .send({ error: "Имя категории не может быть пустым." });
    }
    try {
      const existingCategory = await Category.findOne({
        where: { name: name.trim() },
      });
      if (existingCategory) {
        return res
          .status(400)
          .send({ error: "Категория с таким именем уже существует." });
      }
      const category = await Category.create({ name: name.trim() });
      res.status(201).send({ success: true, category });
    } catch (error) {
      console.error("Ошибка при добавлении категории:", error);
      res.status(500).send({ error: "Ошибка сервера." });
    }
  }
);

// Роут для добавления разработки (AJAX)
app.post(
  "/user/add/development",
  isAuthenticated,
  upload.fields([
    { name: "preview", maxCount: 1 },
    { name: "file_path", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { title, description, category_id } = req.body;
      const userId = req.session.user.id;
      let tags = req.body.tags || [];

      if (!req.files || !req.files["preview"] || !req.files["file_path"]) {
        return res.status(400).json({ error: "Не загружены файлы." });
      }

      // Преобразуем теги в массив чисел
      if (!Array.isArray(tags)) tags = [tags];
      tags = tags.map((id) => parseInt(id)).filter((id) => !isNaN(id));

      // Создаем разработку
      const development = await Development.create({
        title,
        description,
        file_path: `/uploads/${req.files["file_path"][0].filename}`,
        preview: `/uploads/${req.files["preview"][0].filename}`,
        categoryId: parseInt(category_id),
        userId,
      });

      // Добавляем теги
      if (tags.length > 0) {
        const existingTags = await Tag.findAll({
          where: { id: tags },
        });
        await development.addTags(existingTags);
      }

      res.json({
        success: true,
        message: "Разработка успешно добавлена!",
        developmentId: development.id,
      });
    } catch (error) {
      console.error("Ошибка:", error);
      res.status(500).json({ error: "Ошибка при добавлении разработки" });
    }
  }
);

// Роут для удаления разработки (AJAX)
app.post("/user/developments/delete/:id", isAuthenticated, async (req, res) => {
  try {
    const development = await Development.findOne({
      where: {
        id: req.params.id,
        userId: req.session.user.id,
      },
    });

    if (!development) {
      return res.status(404).json({ error: "Разработка не найдена" });
    }

    await development.destroy();
    res.json({ success: true });
  } catch (error) {
    console.error("Ошибка:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Роут для получения данных для редактирования (AJAX)
app.get("/user/developments/edit/:id", isAuthenticated, async (req, res) => {
  try {
    const development = await Development.findOne({
      where: {
        id: req.params.id,
        userId: req.session.user.id,
      },
      include: [
        { model: Category, as: "category" },
        { model: Tag, as: "tags" },
      ],
    });

    if (!development) {
      return res.status(404).json({ error: "Разработка не найдена" });
    }

    res.json({
      development: development.get({ plain: true }),
      categories: await Category.findAll(),
      tags: await Tag.findAll(),
    });
  } catch (error) {
    console.error("Ошибка:", error);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Роут для сохранения редактирования (AJAX)
app.post(
  "/user/developments/update/:id",
  isAuthenticated,
  upload.fields([
    { name: "preview", maxCount: 1 },
    { name: "file_path", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const development = await Development.findOne({
        where: {
          id: req.params.id,
          userId: req.session.user.id,
        },
        include: [{ model: Tag, as: "tags" }], // Добавляем загрузку тегов
      });

      if (!development) {
        return res.status(404).json({ error: "Разработка не найдена" });
      }

      // Сохраняем текущие теги
      const currentTags = development.tags.map((tag) => tag.id);

      // Обновляем данные
      const updateData = {
        title: req.body.title,
        description: req.body.description,
        categoryId: req.body.category_id,
      };

      if (req.files["preview"]) {
        updateData.preview = `/uploads/${req.files["preview"][0].filename}`;
      }

      if (req.files["file_path"]) {
        updateData.file_path = `/uploads/${req.files["file_path"][0].filename}`;
      }

      await development.update(updateData);

      // Обновляем теги только если они были переданы
      let tagIds = currentTags; // По умолчанию оставляем текущие теги
      if (req.body.tags) {
        tagIds = Array.isArray(req.body.tags) ? req.body.tags : [req.body.tags];
        tagIds = tagIds.map((id) => parseInt(id)).filter((id) => !isNaN(id));
      }
      await development.setTags(tagIds);

      res.json({ success: true });
    } catch (error) {
      console.error("Ошибка:", error);
      res.status(500).json({ error: "Ошибка при обновлении" });
    }
  }
);
// Функция для получения списка категорий для админа
app.get(
  "/admin/categories",
  isAuthenticated,
  hasRole("admin"),
  async (req, res) => {
    try {
      const categories = await Category.findAll();
      res.status(200).json(categories);
    } catch (error) {
      console.error("Ошибка получения категорий:", error);
      res.status(500).send("Ошибка сервера");
    }
  }
);

// Функция для получения списка категорий для пользователя
app.get("/user/categories", async (req, res) => {
  try {
    const categories = await Category.findAll();
    res.status(200).json(categories);
  } catch (error) {
    console.error("Ошибка получения категорий:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Функция для получения списка тегов
app.get("/admin/tags", isAuthenticated, hasRole("admin"), async (req, res) => {
  try {
    const tags = await Tag.findAll();
    res.status(200).json(tags);
  } catch (error) {
    console.error("Ошибка получения тегов:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для обработки регистрации
app.post("/register", async (req, res) => {
  const { fullName, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("register", {
      user: req.session.user,
      error: "Пароли не совпадают",
    });
  }
  try {
    const role = await Role.findOne({ where: { name: "user" } });
    if (!role) {
      return res.status(400).send("Роль не найдена");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      fullName,
      email,
      password: hashedPassword,
      roleId: role.id,
    });
    res.redirect("/login");
  } catch (error) {
    let message = "Ошибка регистрации";
    if (error.name === "SequelizeUniqueConstraintError") {
      message = "Пользователь с таким email уже существует";
    } else if (error.errors) {
      message = error.errors.map((err) => err.message).join(", ");
    }
    console.error("Ошибка регистрации:", error);
    res.render("register", { user: req.session.user, error: message });
  }
});

// Роут для страницы авторизации
app.get("/login", (req, res) => {
  res.render("login", { user: req.session.user, error: null });
});

// Роут для обработки авторизации
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ where: { email }, include: Role });
    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.user = {
        id: user.id,
        email: user.email,
        role: user.Role.name,
        fullName: user.fullName,
      };

      if (user.Role.name === "admin") {
        res.redirect("/admin");
      } else {
        res.redirect("/profile");
      }
    } else {
      res.render("login", {
        user: req.session.user,
        error: "Неверный email или пароль",
      });
    }
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.render("login", { user: req.session.user, error: "Ошибка входа" });
  }
});

// Роут для страницы профиля
app.get("/profile", isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;

    // Получаем профиль пользователя
    let profile = await Profile.findOne({ where: { userId } });
    if (!profile) {
      profile = await Profile.create({ userId });
    }

    // Получаем данные пользователя с разработками, категориями и тегами
    const user = await User.findByPk(userId, {
      include: [
        {
          model: Development,
          as: "developments",
          attributes: ["id", "title", "description", "preview", "file_path"],
          include: [
            {
              model: Category,
              as: "category",
              attributes: ["name"],
            },
            {
              model: Tag,
              as: "tags",
              through: { attributes: [] }, // Убираем лишние данные из промежуточной таблицы
            },
          ],
        },
      ],
    });

    // Получаем историю скачиваний отдельно
    const downloadHistory = await DownloadHistory.findAll({
      where: { userId },
      include: [
        {
          model: Development,
          as: "development",
          include: [
            {
              model: Category,
              as: "category",
              attributes: ["name"],
            },
          ],
        },
      ],
      order: [["download_date", "DESC"]],
    });

    if (!user) {
      return res.status(404).send("Пользователь не найден");
    }

    res.render("profile", {
      user: req.session.user,
      profile: profile,
      developments: user.developments || [],
      downloads: downloadHistory || [],
    });
  } catch (error) {
    console.error("Ошибка получения профиля:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Роут для выхода
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("Ошибка при выходе:", err);
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log(`Сервер запущен на порту http://localhost:${port}`);
});
