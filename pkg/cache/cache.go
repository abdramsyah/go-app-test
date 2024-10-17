package cache

import (
	"errors"
	"fmt"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/im7mortal/kmutex"
)

type ICache interface {
	CheckCacheExists(key string) bool
	ReadCache(key string) (data []byte, err error)
	WriteCache(key string, data []byte, ttl time.Duration) (err error)
	WriteCacheIfEmpty(key string, data []byte, ttl time.Duration) (err error)
	DeleteCache(key string) (err error)
	IncrementCache(key string, ttl time.Duration) (incr int64, err error)
}

type cache struct {
	pool   *redis.Pool
	kmutex *kmutex.Kmutex
}

// NewCacheRepository initiate cache repo
func NewCache(pool *redis.Pool) ICache {
	return &cache{
		pool:   pool,
		kmutex: kmutex.New(),
	}
}

func (c *cache) IncrementCache(key string, ttl time.Duration) (incr int64, err error) {
	conn := c.pool.Get()
	defer conn.Close()

	conn.Send("MULTI")
	conn.Send("INCR", key)
	conn.Send("EXPIRE", key, ttl.Seconds())

	res, err := redis.Values(conn.Do("EXEC"))
	if err != nil {
		return
	}
	incr = res[0].(int64)
	return
}

func (c *cache) CheckCacheExists(key string) bool {
	// check whether cache value is empty
	conn := c.pool.Get()
	defer conn.Close()

	exists, _ := redis.Bool(conn.Do("EXISTS", key))

	return exists
}

func (c *cache) ReadCache(key string) (data []byte, err error) {
	c.kmutex.Lock(key)
	defer c.kmutex.Unlock(key)

	// check whether cache value is empty
	conn := c.pool.Get()
	defer conn.Close()

	exists := c.CheckCacheExists(key)
	if exists {
		data, err = redis.Bytes(conn.Do("GET", key))
		return
	}
	return nil, errors.New(fmt.Sprintf("Cache key didn't exists. Key : %s", key))
}

// WriteCache this will and must write the data to cache with corresponding key using locking
func (c *cache) WriteCache(key string, data []byte, ttl time.Duration) (err error) {
	c.kmutex.Lock(key)
	defer c.kmutex.Unlock(key)

	// write data to cache
	conn := c.pool.Get()
	defer conn.Close()

	_, err = conn.Do("SETEX", key, ttl.Seconds(), data)

	return
}

// WriteCacheIfEmpty will try to write to cache, if the data still empty after locking
func (c *cache) WriteCacheIfEmpty(key string, data []byte, ttl time.Duration) (err error) {
	c.kmutex.Lock(key)
	defer c.kmutex.Unlock(key)

	// check whether cache value is empty
	conn := c.pool.Get()
	defer conn.Close()

	_, err = conn.Do("GET", key)
	if err != nil {
		if err == redis.ErrNil {
			return nil //return nil as the data already set, no need to overwrite
		}

		return err
	}

	// write data to cache
	_, err = conn.Do("SETEX", key, ttl.Seconds(), data)
	if err != nil {
		return err
	}

	return nil
}

func (c *cache) DeleteCache(key string) (err error) {
	c.kmutex.Lock(key)
	defer c.kmutex.Unlock(key)

	// write data to cache
	conn := c.pool.Get()
	defer conn.Close()

	_, err = conn.Do("DEL", key)

	return
}
