/*
 * Copyright 2024 gdgd009xcd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.automacrobuilder;

import java.util.HashMap;

/**
 * @author gdgd009xcd
 */
public class TemporaryValueStorage {
    HashMap<String, Object> map;

    public enum Keys {
        // list of the HashMap key.
        K_REQUESTURLREGEX,
        K_RESPONSEURLREGEX,
        K_RESPONSEREGEX,
        K_RESPONSEPART,
        K_RESPONSEPOSITION,
        K_HEADERLENGTH,
        K_COLUMN,
        K_TOKEN,
        K_TOKENTYPE,
        K_URLENCODE,
        K_TARGETPARAM,
        K_FROMPOS,
        K_TOPOS,
        NOP;

        // list of the HashMap value's class associated with Key
        public static final Class<String> Class_K_REQUESTURLREGEX = String.class;
        public static final Class<String> Class_K_RESPONSEURLREGEX = String.class;
        public static final Class<String> Class_K_RESPONSEREGEX = String.class;
        public static final Class<AppValue.HttpSectionTypes> Class_K_RESPONSEPART =
                AppValue.HttpSectionTypes.class;
        public static final Class<String> Class_K_RESPONSEPOSITION = String.class;
        public static final Class<String> Class_K_HEADERLENGTH = String.class;
        public static final Class<String> Class_K_COLUMN = String.class;
        public static final Class<String> Class_K_TOKEN = String.class;
        public static final Class<AppValue.TokenTypeNames> Class_K_TOKENTYPE =
                AppValue.TokenTypeNames.class;
        public static final Class<String> Class_K_URLENCODE = String.class;
        public static final Class<String> Class_K_TARGETPARAM = String.class;
        public static final Class<String> Class_K_FROMPOS = String.class;
        public static final Class<String> Class_K_TOPOS = String.class;
        public static final Class<String> Class_NOP = String.class;
    }

    TemporaryValueStorage() {
        map = new HashMap<String, Object>();
    }

    /**
     * put a value associated with key and clazz
     *
     * @param key
     * @param clazz
     * @param val
     * @param <T>
     */
    public <T> void put(Keys key, Class<T> clazz, T val) {
        map.put(key.name(), val);
    }

    /**
     * put a value associated with key
     *
     * @param i
     * @param key
     * @param clazz
     * @param val
     * @param <T>
     */
    public <T> void put(int i, Keys key, Class<T> clazz, T val) {
        String k = key.name() + ":" + Integer.toString(i); // keyname:n
        map.put(k, val);
    }

    public <T> T get(Keys key, Class<T> clazz) {
        Object o = map.get(key.name());
        return CastUtils.castToType(clazz, o);
    }

    /**
     * get a stored value associated with a "name:i"
     *
     * @param i
     * @param key
     * @param clazz
     * @return String. if specified key data doesn't exist, it returns null.
     * @param <T>
     */
    public <T> T get(int i, Keys key, Class<T> clazz) {
        String k = key.name() + ":" + Integer.toString(i); // "keyname:i"
        return CastUtils.castToType(clazz, map.get(k));
    }

    public void clear() {
        map.clear();
    }
}
