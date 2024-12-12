import random 
import pickle
import ipaddress
import requests
import pandas as pd
import glob
import os
import scipy
from scipy.optimize import minimize_scalar
import numpy as np
import shutil
import time
from util import *
import pyasn
import re

CB_color_cycle = ['#377eb8', '#ff7f00', '#4daf4a',
                    '#f781bf', '#a65628', '#984ea3',
                    '#999999', '#e41a1c', '#dede00']

# helper function to plot results
def plot_result():
    df = pd.read_csv("/home/ubuntu/output-discount.csv")
    
    # aggregate and average over the same date
    res = df.groupby(['date', 'discount'])['roa_coverage_before'].mean().reset_index()
    res = df.groupby(['date', 'discount'], as_index=False)['roa_coverage_before'].mean()

    res2 = df.groupby(['date', 'discount'])['roa_coverage_after'].mean().reset_index()
    res2 = df.groupby(['date', 'discount'], as_index=False)['roa_coverage_after'].mean()

    before3 = res.loc[res['discount'] == 0.3]
    # before5 = res.loc[res['discount'] == 0.5]
    # before8 = res.loc[res['discount'] == 0.8]

    after3 = res2.loc[res2['discount'] == 0.3]
    after5 = res2.loc[res2['discount'] == 0.5]
    after8 = res2.loc[res2['discount'] == 0.8]

    # after3['roa_coverage_after'] = after3['roa_coverage_after'].apply(lambda x: x*100)
    # after5['roa_coverage_after'] = after5['roa_coverage_after'].apply(lambda x: x*100)
    # after8['roa_coverage_after'] = after8['roa_coverage_after'].apply(lambda x: x*100)

    x = before3['date'].tolist()
    
    for i in range(len(x)):
        x[i] = x[i].replace("-01-00","")

    # plt.xlabel('Date', fontsize=20)
    # plt.ylabel('% Tor Clients', fontsize=20)
    # plt.title('Percentage of Clients with ROA Covered Guard',fontsize=24)

    # plt.plot(x, after3['roa_coverage_after'],marker = '.', color = 'blue', label = '30% Discount')
    # plt.plot(x, after5['roa_coverage_after'],marker = '.', color = 'orange', label = '50% Discount')
    # plt.plot(x, after8['roa_coverage_after'],marker = '.', color = 'red', label = '80% Discount')
    # plt.plot(x, before3['roa_coverage_before'],marker = '.', color = 'green', label = " Vanilla Guard Selection")
    # plt.xticks(x, before3['date'], rotation ='vertical')
    # plt.legend()
    # plt.savefig('/home/zzz/Downloads/discount-roa-time.png', bbox_inches='tight')
    
    # # Add a legend
    # plt.legend(loc='upper left', bbox_to_anchor=(1,1), ncol=1)
    
    # # Show graphic
    # plt.show()
    # # plt.savefig('Percentage by categories-discount=1.png')  
    fig, ax = plt.subplots()
    # ax.set_xlabel('Date', fontsize=20)
    ax.set_ylabel('% Tor Clients - PDF', fontsize=24)
    ax.plot(x, after3['roa_coverage_after'].to_numpy(), label='discount = 0.3', color=CB_color_cycle[0], marker='p', markevery=5)
    ax.plot(x, after5['roa_coverage_after'].to_numpy(), label='discount = 0.5', color=CB_color_cycle[1], marker='o', markevery=5)
    ax.plot(x, after8['roa_coverage_after'].to_numpy(), label='discount = 0.8', color=CB_color_cycle[2], marker='v', markevery=5)
    ax.plot(x, before3['roa_coverage_before'].to_numpy(), label='Vanilla Guard Selection (discount = 1)', color=CB_color_cycle[3], marker='s', markevery=5)
    plt.xticks(x[::5], x[::5], rotation ='vertical', fontsize=18)
    plt.legend(loc='lower left', bbox_to_anchor=(0, 1.02, 1, 0.2),
          fancybox=True, shadow=True, ncol=1, fontsize=12)
    # plt.legend(bbox_to_anchor=(1,0), loc="lower right", ncol=1, fontsize=12)
    plt.savefig('perc_clients_roa_discount.png',bbox_inches='tight', dpi=699)

def plot_result3():
    df = pd.read_csv("/home/ubuntu/output-discount-load-optimal.csv")
    
    res1 = df.loc[df['load'] == 0.3]
    res2 = df.loc[df['load'] == 0.5]
    res3 = df.loc[df['load'] == 0.7]
    res4 = df.loc[df['load'] == 0.8]
    res5 = df.loc[df['load'] == 0.9]
    res6 = df.loc[df['load'] == 1]
    

    x = res1['date'].tolist()
    
    for i in range(len(x)):
        x[i] = x[i].replace("-01-00","")

    # plt.xlabel('date')
    # plt.ylabel('optimal discount')
    # plt.title('Optimal discount based on discount and consensuses')
    
    fig, ax = plt.subplots()
    # ax.set_xlabel('date', fontsize=20)
    ax.set_ylabel('Discount', fontsize=20)
    # ax.set_title('Optimal discount based on discount and consensuses',fontsize=24)
    ax.plot(x, res1['discount'].to_numpy(), label='initial load = 0.3', color=CB_color_cycle[0], marker='p', markevery=5)
    ax.plot(x, res2['discount'].to_numpy(), label='initial load = 0.5', color=CB_color_cycle[1], marker='o', markevery=5)
    ax.plot(x, res3['discount'].to_numpy(), label='initial load = 0.7', color=CB_color_cycle[2], marker='v', markevery=5)
    ax.plot(x, res4['discount'].to_numpy(), label='initial load = 0.8', color=CB_color_cycle[3], marker='s', markevery=5)
    ax.plot(x, res5['discount'].to_numpy(), label='initial load = 0.9', color=CB_color_cycle[4], marker='D', markevery=5)
    ax.plot(x, res6['discount'].to_numpy(), label='initial load = 1', color=CB_color_cycle[5], marker='*', markevery=5)
    # plt.legend(bbox_to_anchor=(1,0), loc="lower right", ncol=1, fontsize=12)
    plt.legend(loc='lower left', bbox_to_anchor=(0, 1.02, 1, 0.2),
          fancybox=True, shadow=True, ncol=2, fontsize=12)
    plt.xticks(x[::5], x[::5], rotation ='vertical', fontsize=22)
    # fig.tight_layout()
    # plt.show()
    plt.savefig('discount_x_load.png',bbox_inches='tight', dpi=699)

    # plt.plot(x, res1['discount'],marker = '.', color = 'blue', label = 'load = 0.3')
    # plt.plot(x, res2['discount'],marker = '.', color = 'yellow', label = 'load = 0.5')
    # plt.plot(x, res3['discount'],marker = '.', color = 'red', label = 'load = 0.7')
    # plt.plot(x, res4['discount'],marker = '.', color = 'orange', label = 'load = 0.8')
    # plt.plot(x, res5['discount'],marker = '.', color = 'purple', label = 'load = 0.9')
    # plt.plot(x, res6['discount'],marker = '.', color = 'cyan', label = 'load = 1')
    # plt.xticks(x, res1['date'], rotation ='vertical')
    # plt.legend()
    # plt.savefig('/home/zzz/Downloads/discount-roa-time.png', bbox_inches='tight')
    
    # Add a legend
    # plt.legend(loc='upper left', bbox_to_anchor=(1,1), ncol=1)
    
    # # Show graphic
    # plt.show()
    # # plt.savefig('Percentage by categories-discount=1.png')  


def plot_result5():
    df1 = pd.read_csv("/home/ubuntu/output-matching-new.csv")
    df2 = pd.read_csv("/home/ubuntu/output-matching-plain.csv")
    
    date = df1['date']
    matched_rate_with_churn = df1['matched_after']
    matched_rate_without_churn = df2['matched_after']
    x = date.tolist()
    
    for i in range(len(x)):
        x[i] = x[i].replace("-00", "")

    # ymax = max(matched_rate_with_churn)
    # ymin = min(matched_rate_without_churn)
    # fig = plt.figure(figsize=(16,10), dpi=300)

    # # ymin*0.99 should be changed according to the dataset
    # for ii in range(len(matched_rate_with_churn)):
    #     print(matched_rate_with_churn[ii])
    #     print(matched_rate_without_churn[ii])
    #     plt.text(x[ii]-0.1, ymin*0.99, float(matched_rate_with_churn[ii])-float(matched_rate_without_churn[ii]), size=16)

    # plt.plot(x, matched_rate_with_churn, marker=".", color="#5bc0de")
    # plt.plot(x, matched_rate_without_churn, marker=".", color="#E8743B")
    # plt.ylim([ymin*0.985, ymax*1.01])
    # plt.fill_between(x, matched_rate_with_churn, matched_rate_without_churn, color="grey", alpha=0.3)
    # plt.yticks(matched_rate_with_churn, size=16)
    # plt.xticks(x, size=16)
    
    # plt.show()


    fig, ax = plt.subplots()
    ax.set_xlabel('date', fontsize=20)
    ax.set_ylabel('matched_rate', fontsize=20)
    # ax.set_title('Actual load utilization given load and discount',fontsize=24)
    ax.plot(x, matched_rate_with_churn.to_numpy(), label='with churn', color=CB_color_cycle[0], marker='p', markevery=7)
    ax.plot(x, matched_rate_without_churn.to_numpy(), label='without churn', color=CB_color_cycle[2], marker='o', markevery=7)

    plt.legend(bbox_to_anchor=(1,0), loc="lower right", ncol=1, fontsize=12)
    plt.xticks(x[::14], x[::14], rotation ='vertical', fontsize=18)
    # fig.tight_layout()
    plt.savefig('matched_rate_churn_Jan2024-April2024.png',bbox_inches='tight', dpi=699)

    
def plot_result4():
    df = pd.read_csv("/home/ubuntu/roa-rov-client-2024.csv")
    
    date = df['date']
    roa = df['roa_perc']
    rov = df['rov_perc']
     
    x = date

    # plt.xlabel('discount')
    # plt.ylabel('actual load utilization')
    # plt.title('Actual load utilization given load and discount')

    # plt.plot(x, res1['utilizations'],marker = '.', color = 'blue', label = 'discount = 0.3')
    # plt.plot(x, res2['utilizations'],marker = '.', color = 'yellow', label = 'discount = 0.5')
    # plt.plot(x, res3['utilizations'],marker = '.', color = 'red', label = 'discount = 0.7')
    # plt.plot(x, res4['utilizations'],marker = '.', color = 'orange', label = 'discount = 0.8')
    # plt.plot(x, res5['utilizations'],marker = '.', color = 'purple', label = 'discount = 0.9')
    # plt.plot(x, res6['utilizations'],marker = '.', color = 'cyan', label = 'discount = 1')
    # plt.xticks(x, res1['discount'], rotation ='vertical')

    fig, ax = plt.subplots()
    ax.set_xlabel('date', fontsize=20)
    ax.set_ylabel('client roa/rov distribution', fontsize=20)
    # ax.set_title('Actual load utilization given load and discount',fontsize=24)
    ax.plot(x.to_numpy(), roa.to_numpy(), label='roa', color=CB_color_cycle[0], marker='p', markevery=7)
    ax.plot(x.to_numpy(), rov.to_numpy(), label='rov', color=CB_color_cycle[1], marker='o', markevery=7)

    plt.legend(bbox_to_anchor=(1,0), loc="lower right", ncol=1, fontsize=12)
    plt.xticks(x[::7], date[::7], rotation ='vertical', fontsize=18)
    # fig.tight_layout()
    plt.savefig('roa_rov_distribution_Jan2024-April2024.png',bbox_inches='tight', dpi=699)
    # plt.legend()
    # plt.savefig('/home/zzz/Downloads/discount-roa-time.png', bbox_inches='tight')
    
    # Add a legend
    # plt.legend(loc='upper left', bbox_to_anchor=(1,1), ncol=1)
    
    # Show graphic
    # plt.show()
    # # plt.savefig('Percentage by categories-discount=1.png')  

def plot_result2():
    df = pd.read_csv("/home/ubuntu/output-matching-202405.csv")

    res = df.groupby(['date', 'case'])['matched_before'].mean().reset_index()
    res = df.groupby(['date', 'case'], as_index=False)['matched_before'].mean()

    res2 = df.groupby(['date', 'case'])['matched_after'].mean().reset_index()
    res2 = df.groupby(['date', 'case'], as_index=False)['matched_after'].mean()

    before1 = res.loc[res['case'] == "no added rov"]
    before3 = res.loc[res['case'] == "manrs-high"]
    before2 = res.loc[res['case'] == "RoVISTA"]
    before4 = res.loc[res['case'] == "Shulman group"]
    before5 = res.loc[res['case'] == "manrs-low"]

    after1 = res2.loc[res2['case'] == "no added rov"]
    after3 = res2.loc[res2['case'] == "manrs-high"]
    after2 = res2.loc[res2['case'] == "RoVISTA"]
    after4 = res2.loc[res2['case'] == "Shulman group"]
    after5 = res2.loc[res2['case'] == "manrs-low"]

    y1 = [float(before1['matched_before']), float(before3['matched_before']), float(before2['matched_before']), float(before4['matched_before']), float(before5['matched_before'])]
    y2 = [float(after1['matched_after']), float(after3['matched_after']), float(after2['matched_after']), float(after4['matched_after']), float(after5['matched_after'])]


    y1 = [float(before1['matched_before']), float(before3['matched_before']), float(before2['matched_before']), float(before4['matched_before']), float(before5['matched_before'])]
    y2 = [float(after1['matched_after']), float(after3['matched_after']), float(after2['matched_after']), float(after4['matched_after']), float(after5['matched_after'])]


    for i in range(len(y1)):
        print(y2[i]/y1[i])

    barWidth = 0.25
    fig = plt.subplots(figsize =(12, 8))
    br1 = np.arange(len(y1))
    br2 = [x + barWidth for x in br1]

    plt.bar(br1, y1, width = barWidth, edgecolor ='grey', label ='before optimization', color=CB_color_cycle[0])
    plt.bar(br2, y2, width = barWidth, edgecolor ='grey', label ='after optimization', color=CB_color_cycle[1])

    plt.xlabel('ROV data source', fontweight ='bold', fontsize = 24)
    plt.ylabel('%  ROA ROV matched pairs', fontweight ='bold', fontsize = 24)
    #plt.title('Percentage of ROA ROV matched client-relay pairs', fontsize=24)
    # plt.xticks([r + barWidth for r in range(len(y1))], ["no added rov", "top 100", " top 20%", "rov match all roa", "random 10%"])
    plt.xticks([r + barWidth for r in range(len(y1))], ["base", "manrs-high", "RoVISTA", "Hlavacek", "manrs-low"])
    plt.xticks(fontsize=22)
    plt.yticks(fontsize=22)
    plt.legend(fontsize=22)
    # plt.show()
    plt.savefig('matching-results.png', bbox_inches='tight', dpi=599)
    
plot_result()
plot_result2()
plot_result3()
plot_result4()
plot_result5()
