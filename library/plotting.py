from IPython.display import Image
import matplotlib.pyplot as plt
import numpy as np

# Marker Styles: http://matplotlib.org/api/markers_api.html
def plot(data, x_row=0, x_label="Thresholds", x_tick_step=3, y_rows=[1], y_labels=["data"], y_markers=["o"],y_colors=["c"], cluster_plot_file="out.png", figure_size=(20,10) ):

    x = np.array(data[:,x_row])

    y_stack = np.row_stack(np.transpose(data[:,1:]))
    fig = plt.figure(figsize=figure_size)
    ax1 = fig.add_subplot(111)

    for i,y_row_id in enumerate(y_rows):
        ax1.plot(x, y_stack[y_row_id,:], label=y_labels[i], color=y_colors[i], marker=y_markers[i])

    plt.xticks([step for i,step in enumerate(x) if i%x_tick_step==0])
    plt.xlabel(x_label)

    handles, labels = ax1.get_legend_handles_labels()
    lgd = ax1.legend(handles, labels, loc='lower center')
    ax1.grid('on')

    plt.savefig(cluster_plot_file)
    plt.close()
