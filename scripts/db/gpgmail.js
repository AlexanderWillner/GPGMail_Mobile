var db = null;

try {
    if (window.openDatabase) {
        db = openDatabase("GPGMail", "1.0", "GPGMail mobile", 200000);
        if (!db)
            alert("Failed to open the database on disk.  This is probably because the version was bad or there is not enough space left in this domain's quota");
    } else {
        alert("Couldn't open the database.");
    }
} catch(err) {
    db = null;
    alert("Couldn't open the database (exception).");
}

function loaded() {
    db.transaction(function(tx) {
        tx.executeSql("SELECT COUNT(*) FROM Options", [], function(result) {
            /**/;
        }, function(tx, error) {
            tx.executeSql("CREATE TABLE Options (id REAL UNIQUE, defaultSign TEXT, defaultVerify TEXT)", [], function(result) { 
                addTestEntries();
            });
        });
    });
}

function addTestEntries() {
    db.transaction(function (tx) {
        tx.executeSql("INSERT INTO Options (id, defaultSign, defaultVerify) VALUES (?, ?, ?)", [1, 1, 1]);
    }); 
}

function dbSetDefaultSign(isSet) {
    db.transaction(function (tx) {
        tx.executeSql("UPDATE Options SET defaultSign = ? WHERE id = 1", [isSet]);
    }); 
}

function dbIsDefaultSign() {
    db.transaction(function (tx) {
        tx.executeSql("SELECT defaultSign FROM Options WHERE id = 1", [], function(result) { /* todo. */ }, function(tx, error) {dbError(tx, error)});
    }); 
}

function dbError(tx, error) {
    alert ("Database error!");
}

if (db != null)
    addEventListener('load', loaded, false);
    

function dbSave() {
    alert ("Not implemented yet");
}