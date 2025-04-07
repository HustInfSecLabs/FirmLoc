import matplotlib.pyplot as plt

# 假设的Star数和Fork数
data = {'Stars': 2850, 'Forks': 319}
labels = list(data.keys())
values = list(data.values())

# 创建条形图
plt.bar(labels, values, color=['blue', 'green'])
plt.title('camel-ai Camel Framework on GitHub')
plt.ylabel('Count')

# 保存图像到本地
plt.savefig('camel_ai_github_stats.png')

# 显示图表
plt.show()