defmodule MachineManager.Parallel do
	@doc """
	Waits for all tasks in `task_map` to complete (a map of task_name -> Task).
	Whenever a task completes, calls `completion_fn` with two arguments, either
		`task_name, {:ok, task_result}` or
		`task_name, {:exit, reason}`
	Checks for completion every `check_interval` milliseconds.
	Every check interval, calls `waiting_fn` with a `waiting_task_map` of
	still-waiting tasks.
	"""
	@spec block_on_tasks(map, (String.t, term -> term), (map -> term), integer) :: nil
	def block_on_tasks(task_map, completion_fn, waiting_fn, check_interval) do
		pid_to_task_name =
			task_map
			|> Enum.map(fn {task_name, task} -> {task.pid, task_name} end)
			|> Map.new
		waiting_task_map = for {task, result} <- Task.yield_many(task_map |> Map.values, check_interval) do
			task_name = pid_to_task_name[task.pid] || \
				raise(RuntimeError, "task_name == nil for #{inspect task}")
			case result do
				{:ok, task_result} -> completion_fn.(task_name, {:ok, task_result}); nil
				{:exit, reason}    -> completion_fn.(task_name, {:exit, reason});    nil
				nil                -> {task_name, task}
			end
		end |> Enum.reject(&is_nil/1) |> Map.new
		if waiting_task_map != %{} do
			waiting_fn.(waiting_task_map)
			block_on_tasks(waiting_task_map, completion_fn, waiting_fn, check_interval)
		end
	end
end
