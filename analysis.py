from datetime import datetime, timedelta
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
from math import sqrt
from pymongo import UpdateOne

# this function takes the incoming data and the daily_report_collection object (for throwing retrospective requests) as parameters,
def analyze(data, hostnames, daily_report_colection, anomaly_colection, analysis_time=30, lower_bound=20):
    stabilization_analysis_time = iqr_analysis_time
    stabilization_analysis_treshold = int(stabilization_analysis_time*2/3)
    iqr_analysis_time = analysis_time//2
    iqr_analysis_treshold = int(iqr_analysis_time*2/3)
    end = data[0]['date']
    gun_degeri = datetime.strptime(end, '%Y-%m-%d').day
    
    # Here we calculate begin value for iqr based on analaysis_time We will get the data coming between begin and end
    begin_for_iqr = datetime.strptime(end, '%Y-%m-%d') - timedelta(days=iqr_analysis_time)
    begin_for_iqr = begin_for_iqr.strftime('%Y-%m-%d')

    begin_for_stabilization = datetime.strptime(end, '%Y-%m-%d') - timedelta(days=stabilization_analysis_time)
    begin_for_stabilization = begin_for_stabilization.strftime('%Y-%m-%d')

    # Here we create a query to be sent to mongoDB
    hostfquery = [{'hostname':i} for i in hostnames]
    query_iqr = {"date":{"$gte": begin_for_iqr, "$lte": end}, "$or": hostfquery}
    query_stabilization = {"date":{"$gte": begin_for_stabilization, "$lte": end}, "$or": hostfquery}
    
    # We turn the result of the query for iqr and stabilization into a pandas dataframe
    doc_iqr = daily_report_colection.find(query_iqr)
    df_iqr =  pd.DataFrame(list(doc_iqr))

    doc_stabilization = daily_report_colection.find(query_stabilization)
    df_stabilization =  pd.DataFrame(list(doc_stabilization))

    # we start an empty anomaly list then fill this list with detected anomalies
    anomaly_list = []
    
    # Since anomaly analysis will be done separately for each hostname, we are going through all the hostnames one by one.
    #  These hostname values correspond to a column on the event matrix.
    for i in hostnames:
        df_filtered_hostname_iqr = df_iqr[df_iqr['hostname'].str.strip()==i]
        df_filtered_hostname_stabilization = df_stabilization[df_stabilization['hostname'].str.strip()==i]

        
        if len(df_filtered_hostname_stabilization) >= stabilization_analysis_treshold:
            clustering_result_df = clustering(df_filtered_hostname_stabilization, stabilization_analysis_time)

            if not clustering_result_df.empty:
                
                clustering_result_dict = clustering_result_df.to_dict('records')
                clustering_result_dict_copy = clustering_result_dict.copy()
                
                for eleman in clustering_result_dict:
                    if eleman['hitcount']  < lower_bound:
                        clustering_result_dict_copy.remove(eleman)
                if clustering_result_dict_copy:   
                    # We insert each anomaly detected with k-means to mongoDB
                    upserts=[ UpdateOne({'Start Time (Minimum)':i['Start Time (Minimum)']}, {'$setOnInsert':i}, upsert=True) for i in clustering_result_dict_copy]
                    result = anomaly_colection.bulk_write(upserts)

        
        if len(df_filtered_hostname_iqr) >= iqr_analysis_treshold and len(df_filtered_hostname_stabilization) >= stabilization_analysis_treshold:
            anomaly_df_iqr, importance_iqr = calculate_IQR(df_filtered_hostname_iqr, end)
            anomaly_df_stabilization, importance_stabilization = calculate_stabilization(df_filtered_hostname_stabilization, end)
            anomaly_dict_iqr = anomaly_df_iqr.to_dict('records')
            anomaly_dict_stabilization = anomaly_df_stabilization.to_dict('records')

            # Here we look at which algorithms caught anomalies and mark the importance values
            if len(anomaly_dict_iqr) > 0 and len(anomaly_dict_stabilization) > 0:
                if anomaly_dict_stabilization[0]['hitcount']>lower_bound:
                    anomaly_dict_iqr[0]['algorithms']=["quartile", "stabilization"]
                    anomaly_dict_iqr[0]['performedDays']=analysis_time
                    anomaly_dict_iqr[0]['importance']=importance_stabilization
                    anomaly_list.append(anomaly_dict_iqr[0])
            elif(len(anomaly_dict_iqr) > 0):
                anomaly_dict_iqr[0]['algorithms']=["quartile"]
                anomaly_dict_iqr[0]['performedDays']=analysis_time//2
                anomaly_dict_iqr[0]['importance']=importance_iqr
                anomaly_list.append(anomaly_dict_iqr[0])
            elif(len(anomaly_dict_stabilization) > 0):
                if anomaly_dict_stabilization[0]['hitcount']>lower_bound:
                    anomaly_dict_stabilization[0]['algorithms']=["stabilization"]
                    anomaly_dict_stabilization[0]['performedDays']=analysis_time
                    anomaly_dict_stabilization[0]['importance']=importance_stabilization
                    # son olarak en üstte boş olarak tanımlanan anomali listesine eklemeyi yapıyoruz
                    anomaly_list.append(anomaly_dict_stabilization[0])
      
        elif len(df_filtered_hostname_iqr) >= iqr_analysis_treshold:
            anomaly_df_iqr, importance_iqr = calculate_IQR(df_filtered_hostname_iqr, end)
            anomaly_dict_iqr = anomaly_df_iqr.to_dict('records')
            if(len(anomaly_dict_iqr) > 0):
                anomaly_dict_iqr[0]['algorithms']=["quartile"]
                anomaly_dict_iqr[0]['performedDays']=analysis_time//2
                anomaly_dict_iqr[0]['importance']=importance_iqr
                anomaly_list.append(anomaly_dict_iqr[0])
        
        elif len(df_filtered_hostname_stabilization) >= stabilization_analysis_treshold:
            anomaly_df_stabilization, importance_stabilization = calculate_stabilization(df_filtered_hostname_iqr, end)
            anomaly_dict_stabilization = anomaly_df_stabilization.to_dict('records')
            if(len(anomaly_dict_stabilization) > 0):
                anomaly_dict_stabilization[0]['algorithms']=["stabilization"]
                anomaly_dict_stabilization[0]['performedDays']=analysis_time
                anomaly_dict_stabilization[0]['importance']=importance_stabilization
                anomaly_list.append(anomaly_dict_stabilization[0])

    # We insert the anomalies detected as a result of the analyzes to the database.
    if len(anomaly_list) > 0:
        anomaly_list = [dict(item, note='') for item in anomaly_list]
        now = datetime.now()
        year = '{:02d}'.format(now.year)
        month = '{:02d}'.format(now.month)
        day = '{:02d}'.format(now.day)
        year_motnh_day = '{}-{}-{}'.format(year, month, day)
        anomaly_list = [dict(item, lastUpdate=year_motnh_day) for item in anomaly_list]
        anomaly_colection.insert_many(anomaly_list)

    


def calculate_IQR(df, date, lower_bound = 100, coefficient=1.5):
    Q1=df['hitcount'].quantile(0.25)
    Q3=df['hitcount'].quantile(0.75)
    IQR=Q3-Q1
    upper_bound = Q3+coefficient*IQR
    df_final=df[(df['hitcount'] > upper_bound)]
    df_final = df_final.drop(columns='_id')
    df_final = df_final[df_final['date'].str.contains(str(date))]
    df_final = df_final[(df_final['hitcount'] > lower_bound)]

    degree = 'low'
    if df_final.shape[0] < 1:
        return pd.DataFrame(), degree
    hitcount_of_anomaly = df_final['hitcount'].iat[0]
    
    if hitcount_of_anomaly > upper_bound*4:
        degree = 'high'
    elif hitcount_of_anomaly > upper_bound*2:
        degree = 'middle'
        return df_final, degree
    elif hitcount_of_anomaly > upper_bound:
        return df_final, degree
    return pd.DataFrame(), degree

def calculate_stabilization(df, date, tolerance=10):
   
    Q1=df['hitcount'].quantile(0.25)
    Q3=df['hitcount'].quantile(0.75)
    IQR=Q3-Q1
    df_final=df[(df['hitcount'] < (Q1-1.5*IQR))]
    degree = 'low'
    if df_final.shape[0] <= tolerance//4:
        degree = 'high'
        df = df.drop(columns='_id')
        df = df[df['date'].str.contains(str(date))]
        return df, degree
    elif df_final.shape[0] <= tolerance//2:
        degree = 'middle'
        df = df.drop(columns='_id')
        df = df[df['date'].str.contains(str(date))]
        return df, degree
    elif df_final.shape[0] <= tolerance:
        degree = 'low'
        df = df.drop(columns='_id')
        df = df[df['date'].str.contains(str(date))]
        return df, degree
    return pd.DataFrame(), degree

def clustering(df, analysis_time = 30, upper_bound = 0.75):
    scaler = MinMaxScaler()
    df[['hitcount_scaled']] = scaler.fit_transform(df[['hitcount']])
    kmeans = KMeans(n_clusters = 1).fit(df[['hitcount_scaled']])
    center = kmeans.cluster_centers_
    df['distances'] = [sqrt((i - center)**2) for i in df['hitcount_scaled']]
    df_final = df[(df['distances'] > upper_bound) & (df['hitcount'] > df['hitcount'].mean())]
    
    if df_final.shape[0] < 1:
        return pd.DataFrame()

    distance_of_anomaly = df_final['distances'].iat[0]
    degree = 'low'
    if distance_of_anomaly > upper_bound+0.20:
        degree = 'high'
        df_final['algorithms'] = 'k-means'
        df_final['performedDays'] = analysis_time
        df_final['importance'] = degree
        return df_final
    elif distance_of_anomaly > upper_bound+0.10:
        degree = 'middle'
        df_final['algorithms'] = 'k-means'
        df_final['performedDays'] = analysis_time
        df_final['importance'] = degree
        return df_final
    elif distance_of_anomaly > upper_bound:
        df_final['algorithms'] = 'k-means'
        df_final['performedDays'] = analysis_time
        df_final['importance'] = degree
        return df_final


    return pd.Dataframe()
