package org.mimoproxy.reka.test;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.ParcelFileDescriptor;
import java.io.File;
import java.io.FileNotFoundException;

/** ADB-only read access to this test app's fixed acceptance report. */
public final class ReportProvider extends ContentProvider {
    public boolean onCreate() { return true; }
    public String getType(Uri uri) { return "application/json"; }
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        int uid = Binder.getCallingUid();
        if (uid != 2000 && uid != 0 && uid != android.os.Process.myUid()) throw new SecurityException("ADB only");
        if (!mode.equals("r") || !uri.getPath().equals("/power")) throw new FileNotFoundException("unknown report");
        return ParcelFileDescriptor.open(new File(getContext().getFilesDir(), "power-report.json"), ParcelFileDescriptor.MODE_READ_ONLY);
    }
    public Cursor query(Uri uri, String[] columns, String selection, String[] values, String sort) { return null; }
    public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
    public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
