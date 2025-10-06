import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

export default async function handler(req, res) {
  await client.connect();
  const db = client.db();
  const collection = db.collection('data');
  const data = await collection.find({}).toArray();
  res.status(200).json(data);
}
