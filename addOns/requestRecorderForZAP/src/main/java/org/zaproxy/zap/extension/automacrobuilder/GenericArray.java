package org.zaproxy.zap.extension.automacrobuilder;

import java.lang.reflect.Array;

/**
 * Create Generic Array.
 *
 * <p>Note: <br>
 * From java se api document,<br>
 * The number of dimensions of the new array must not exceed 255.<br>
 * GenericArray throws an IllegalArgumentException<br>
 * when assigning a class with 255 or more dimensions array to type parameter T.
 *
 * <p>
 *
 * @param <T>
 */
public class GenericArray<T> {
    private final T[] genericArray;

    @SuppressWarnings({"cast", "unchecked"})
    public GenericArray(Class<T> classType, int size) {
        this.genericArray = (T[]) Array.newInstance(classType, size);
    }

    @SuppressWarnings({"cast", "unchecked"})
    public GenericArray(T object, int size) {
        this.genericArray = (T[]) Array.newInstance(object.getClass(), size);
    }

    @SuppressWarnings("cast")
    public T get(int index) {
        return (T) this.genericArray[index];
    }

    public T[] getArray() {
        return this.genericArray;
    }

    public void set(int index, T item) {
        this.genericArray[index] = item;
    }

    public int size() {
        return this.genericArray.length;
    }
}
