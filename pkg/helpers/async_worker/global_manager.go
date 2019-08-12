package async_worker

var GlobalManager ManagerType

func init() {
	GlobalManager = new(Manager)
}
