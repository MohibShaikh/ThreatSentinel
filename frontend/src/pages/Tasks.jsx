import React from 'react';
import { ListTodo, Clock, CheckCircle } from 'lucide-react';

const Tasks = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Tasks</h1>
          <p className="text-gray-400 mt-1">Priority-based task queue and management</p>
        </div>
        <button className="btn-primary flex items-center space-x-2">
          <ListTodo className="w-4 h-4" />
          <span>Add Task</span>
        </button>
      </div>
      
      <div className="card p-6">
        <div className="text-center py-12">
          <Clock className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Task Management Coming Soon</h2>
          <p className="text-gray-400">Priority-based task queue with status tracking and management.</p>
        </div>
      </div>
    </div>
  );
};

export default Tasks; 