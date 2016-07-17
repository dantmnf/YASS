using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace YASS
{
    public class ConcurrentLRUCache<K, V>
    {
        private object l = new object();
        private int capacity;
        private Dictionary<K, LinkedListNode<CacheItem<K, V>>> cacheMap = new Dictionary<K, LinkedListNode<CacheItem<K, V>>>();
        private LinkedList<CacheItem<K, V>> lruList = new LinkedList<CacheItem<K, V>>();

        public ConcurrentLRUCache(int capacity)
        {
            this.capacity = capacity;
        }
        public V GetValue(K key)
        {
            lock (l)
            {
                LinkedListNode<CacheItem<K, V>> node;
                if (cacheMap.TryGetValue(key, out node))
                {
                    V value = node.Value.value;
                    lruList.Remove(node);
                    lruList.AddLast(node);
                    return value;
                }
                return default(V);
            }
        }
        public void Add(K key, V val)
        {
            lock (l)
            {
                if (cacheMap.Count >= capacity)
                {
                    RemoveFirst();
                }

                CacheItem<K, V> cacheItem = new CacheItem<K, V>(key, val);
                LinkedListNode<CacheItem<K, V>> node = new LinkedListNode<CacheItem<K, V>>(cacheItem);
                lruList.AddLast(node);
                cacheMap.Add(key, node);
            }
        }

        public void Clear()
        {
            lock (l)
            {
                foreach (var item in cacheMap)
                {
                    (item.Value.Value.value as IDisposable)?.Dispose();
                }
            }
        }

        private void RemoveFirst()
        {
            lock (l)
            {
                // Remove from LRUPriority
                LinkedListNode<CacheItem<K, V>> node = lruList.First;
                lruList.RemoveFirst();
                // Remove from cache
                cacheMap.Remove(node.Value.key);
                (node.Value.value as IDisposable)?.Dispose();
            }
        }
        public class CacheItem<Key, Value>
        {
            public CacheItem(Key k, Value v)
            {
                key = k;
                value = v;
            }
            public Key key;
            public Value value;
        }
    }
}
