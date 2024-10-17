package repository

import (
	"fmt"
	"go-tech/internal/app/commons"
	"go-tech/internal/app/dto"
	"go-tech/internal/app/model"
	"log"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ITaskRepository interface {
	Count(ctx echo.Context, filter *dto.TaskFilter) (count int64, err error)
	Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.TaskFilter) (users []model.Task, err error)
	FindByID(ctx echo.Context, ID primitive.ObjectID) (task model.Task, err error)
	Create(ctx echo.Context, user *model.Task) (err error)
	Update(ctx echo.Context, task *model.Task, ID primitive.ObjectID) (err error)
	Delete(ctx echo.Context, ID primitive.ObjectID, userID uint) (err error)
}

type taskRepository struct {
	opt Option
}

func NewTaskRepository(opt Option) ITaskRepository {
	return &taskRepository{
		opt: opt,
	}
}

func (r *taskRepository) generateCondition(filter *dto.TaskFilter) (query bson.M) {
	// Jika filter.Search tidak nil, tambahkan query untuk pencarian
	if filter.Search != nil {
		searchPattern := primitive.Regex{Pattern: "^" + *filter.Search, Options: "i"}

		// Menggunakan $or untuk mencocokkan `code`, `name`, atau `level`
		query["$or"] = []bson.M{
			{"code": bson.M{"$regex": searchPattern}},  // `code` seperti filter.Search
			{"name": bson.M{"$regex": searchPattern}},  // `name` seperti filter.Search
			{"level": bson.M{"$regex": searchPattern}}, // `level` seperti filter.Search
		}
	}

	return query
}

func (r *taskRepository) Count(ctx echo.Context, filter *dto.TaskFilter) (count int64, err error) {
	collection := r.opt.MongoDB.Collection("task")
	query := r.generateCondition(filter)

	count, err = collection.CountDocuments(ctx.Request().Context(), query)
	if err != nil {
		return 0, err
	}
	return
}

func (r *taskRepository) Find(ctx echo.Context, pConfig commons.PaginationConfig, filter *dto.TaskFilter) (users []model.Task, err error) {
	collection := r.opt.MongoDB.Collection("task")
	query := r.generateCondition(filter)

	findOptions := options.Find()
	// findOptions.SetSort(bson.D{{"id", -1}})                             // Mengurutkan berdasarkan id DESC
	// findOptions.SetSkip(int64((pConfig.Offset - 1) * pConfig.PageSize)) // Pagination skip
	// findOptions.SetLimit(int64(pConfig.PageSize))                       // Batas jumlah data per page

	// Query ke MongoDB
	cursor, err := collection.Find(ctx.Request().Context(), query, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx.Request().Context())

	// Decode hasil query ke slice of users
	err = cursor.All(ctx.Request().Context(), &users)
	if err != nil {
		return nil, err
	}
	return
}

func (r *taskRepository) FindByID(ctx echo.Context, ID primitive.ObjectID) (task model.Task, err error) {
	collection := r.opt.MongoDB.Collection("task")
	filter := bson.M{"_id": ID}
	err = collection.FindOne(ctx.Request().Context(), filter).Decode(&task)
	return
}

func (r *taskRepository) Update(ctx echo.Context, task *model.Task, ID primitive.ObjectID) (err error) {
	collection := r.opt.MongoDB.Collection("task")
	filter := bson.M{"_id": ID}

	update := bson.M{
		"$set": bson.M{
			"title":       task.Title,
			"description": task.Description,
			"status":      task.Status,
		},
	}

	_, err = collection.UpdateOne(ctx.Request().Context(), filter, update, options.Update())
	if err != nil {
		log.Printf("Failed to update task: %v\n", err)
		return err
	}

	return nil
}

func (r *taskRepository) Create(ctx echo.Context, task *model.Task) (err error) {
	log.Printf("Task Data: %+v\n", task)
	collection := r.opt.MongoDB.Collection("task")

	log.Printf("Inserting task: %+v\n", task)
	// Menambahkan task baru ke dalam koleksi
	// _, err = collection.InsertOne(context.TODO(), task)
	_, err = collection.InsertOne(ctx.Request().Context(), task)
	if err != nil {
		log.Printf("Failed to insert task: %v\n", err)
		// Menangani error jika gagal menyimpan task
		return err
	}

	log.Println("Task successfully inserted")
	// MongoDB tidak menggunakan ID integer, jadi tidak ada pengembalian ID
	return nil
}

func (r *taskRepository) Delete(ctx echo.Context, ID primitive.ObjectID, userID uint) (err error) {
	collection := r.opt.MongoDB.Collection("task")

	filter := bson.M{"_id": ID}

	_, err = collection.DeleteOne(ctx.Request().Context(), filter)
	if err != nil {
		fmt.Printf("Failed to delete task: %v\n", err)
		return err
	}

	fmt.Println("Task successfully deleted")
	return nil
}
