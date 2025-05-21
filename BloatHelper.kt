import java.io.File
fun watchAndNotify(path: String, onChange: (File) -> Unit) = 
    java.nio.file.FileSystems.getDefault().newWatchService().apply {
        File(path).toPath().register(this, java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY)
        while (true) onChange(File((take().pollEvents()[0].context() as java.nio.file.Path).toString()))
    }
